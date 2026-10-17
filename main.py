import os
import re
import asyncio
import json
import time
import logging
from collections import defaultdict, deque

import discord
from discord import app_commands

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ============================ НАСТРОЙКИ ============================
# Только эти пользователи имеют доступ к панели и командам (команды видны всем)
ALLOWED_IDS = {1433908056944676989}

# Каналы логов по умолчанию (можно поменять в панели: /panel → «Каналы логов»)
LOG_CHANNELS_DEFAULT = {
    "join": 1558139119610105988,     # заходы на сервер
    "ban": 1558139410007203840,      # баны, разбаны, кики
    "voice": 1558140516603011183,    # муты и отключения из голосовых
    "timeout": 1558139549677527122,  # тайм-ауты
    "move": 1558140353931124806,     # перемещения между голосовыми каналами
    "server": 1556045690604486746,   # создание/изменение каналов и ролей
    "automod": 1556045690604486746,  # предупреждения, удалённые сообщения, снятие ролей
}
DATA_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data.json")
TOKEN = os.getenv("TOKEN") or os.getenv("DISCORD_TOKEN") or os.getenv("BOT_TOKEN")
# ===================================================================

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("automod")

RULE_NAMES = {
    "invite": "Ссылки на другие Discord-серверы",
    "duplicate": "Одинаковые сообщения (спам)",
    "mentions": "Массовые упоминания",
    "phishing": "Скам / фишинг / ссылки-перенаправления",
    "crypto": "Крипто-реклама",
    "shortlink": "Короткие и опасные ссылки",
}
ACTION_NAMES = {
    "delete": "Только удалить сообщение",
    "warn": "Выдать предупреждение",
    "ban": "Забанить",
    "strip": "Снять все роли",
}
LIMIT_ACTION_NAMES = {"ban": "Бан", "strip": "Снятие всех ролей"}
LOG_NAMES = {
    "join": "Заходы на сервер",
    "ban": "Баны и кики",
    "voice": "Муты и отключения из голосовых",
    "timeout": "Тайм-ауты",
    "move": "Перемещения в голосовых",
    "server": "Каналы и роли",
    "automod": "Автомодерация",
}

DEFAULT_CONFIG = {
    "log_channels": dict(LOG_CHANNELS_DEFAULT),
    "max_warns": 3,
    "warn_ttl": 24,   # через сколько часов предупреждение сгорает (0 = никогда)
    "stripped": {},   # снятые роли (для амнистии)
    "limit_action": "ban",
    "whitelist": [],
    "warns": {},
    "rules": {
        "invite": {"enabled": True, "action": "ban", "warns": 1},
        "duplicate": {"enabled": True, "action": "warn", "warns": 1, "count": 3, "window": 30},
        "mentions": {"enabled": True, "action": "warn", "warns": 1, "limit": 5},
        "phishing": {"enabled": True, "action": "ban", "warns": 1},
        "crypto": {"enabled": True, "action": "warn", "warns": 1},
        "shortlink": {"enabled": True, "action": "warn", "warns": 1},
    },
}

# ============================ РЕГУЛЯРКИ ============================
INVITE_RE = re.compile(
    r"(?:discord(?:app)?\.com/invite|discord\.gg|dsc\.gg)/([A-Za-z0-9-]+)", re.IGNORECASE
)
PHISH_RE = re.compile(
    r"\[(?:https?://|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})[^\]]*\]\(https?://[^)]+\)"
)
PHISH_DOMAINS_RE = re.compile(
    r"(?:discord-?nitro|discordgift|discord-gift|dlscord|discorcl|steamcommunlty|steancommunity)"
    r"[a-z0-9.-]*\.[a-z]{2,}",
    re.IGNORECASE,
)
CRYPTO_RE = re.compile(
    r"(crypto|bitcoin|ethereum|инвестирование|заработок|быстрые деньги)", re.IGNORECASE
)
SHORT_RE = re.compile(r"(bit\.ly|tinyurl\.com|short\.link|ow\.ly)", re.IGNORECASE)


# ============================ ХРАНИЛИЩЕ ============================
def load_config():
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if os.path.exists(DATA_FILE):
        try:
            with open(DATA_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
            for k in ("max_warns", "limit_action", "whitelist", "warns", "warn_ttl", "stripped"):
                if k in saved:
                    cfg[k] = saved[k]
            for lk, lv in saved.get("log_channels", {}).items():
                if lk in cfg["log_channels"]:
                    cfg["log_channels"][lk] = lv
            for rk, rv in saved.get("rules", {}).items():
                if rk in cfg["rules"]:
                    cfg["rules"][rk].update(rv)
        except Exception as e:
            log.error("Не удалось прочитать data.json: %s", e)
    return cfg


cfg = load_config()

# Миграция старого формата: число предупреждений -> список времён выдачи
for _uid, _v in list(cfg["warns"].items()):
    if isinstance(_v, int):
        if _v > 0:
            cfg["warns"][_uid] = [time.time()] * _v
        else:
            del cfg["warns"][_uid]


def ttl_text():
    h = cfg["warn_ttl"]
    return "никогда" if h == 0 else f"{h} ч."


def prune_user(uid):
    ttl = cfg["warn_ttl"] * 3600
    lst = cfg["warns"].get(uid, [])
    if ttl:
        now = time.time()
        lst = [t for t in lst if now - t < ttl]
    if lst:
        cfg["warns"][uid] = lst
    else:
        cfg["warns"].pop(uid, None)
    return lst


def active_warns(uid):
    return prune_user(uid)


def prune_all():
    changed = False
    for uid in list(cfg["warns"].keys()):
        before = len(cfg["warns"][uid])
        if len(prune_user(uid)) != before:
            changed = True
    return changed


async def warn_cleanup_loop():
    await bot.wait_until_ready()
    while not bot.is_closed():
        try:
            if prune_all():
                save()
        except Exception:
            log.exception("Ошибка очистки предупреждений")
        await asyncio.sleep(60)


def save():
    tmp = DATA_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    os.replace(tmp, DATA_FILE)


def is_admin(user) -> bool:
    return user.id in ALLOWED_IDS


# ============================ БОТ ============================
intents = discord.Intents.default()
intents.message_content = True
intents.members = True
intents.guilds = True
intents.moderation = True     # события журнала аудита (баны, кики, тайм-ауты)
intents.voice_states = True   # выходы из голосовых (для лога отключений)


class AutoModBot(discord.Client):
    def __init__(self):
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)

    async def setup_hook(self):
        self.loop.create_task(warn_cleanup_loop())

    async def sync_guild(self, guild):
        try:
            self.tree.copy_global_to(guild=guild)
            await self.tree.sync(guild=guild)
        except Exception as e:
            log.error("Синхронизация команд для %s не удалась: %s", guild.id, e)

    async def on_ready(self):
        for g in self.guilds:
            await self.sync_guild(g)
            await refresh_own_invites(g, force=True)
            try:
                for line in await check_log_channels(g):
                    if line.startswith("❌"):
                        log.warning("[%s] %s", g.name, line.replace("**", ""))
            except Exception:
                log.exception("Не удалось проверить каналы логов")
        log.info("Бот запущен как %s", self.user)

    async def on_guild_join(self, guild):
        await self.sync_guild(guild)


bot = AutoModBot()

invite_cache: dict[str, tuple[float, int | None]] = {}
own_invites: dict[int, set[str]] = {}      # приглашения НАШЕГО сервера (коды в нижнем регистре)
own_invites_time: dict[int, float] = {}
recent_bans: dict[tuple[int, int], float] = {}  # чтобы не банить одного человека 10 раз подряд
history: dict[tuple[int, int], deque] = defaultdict(deque)


# ============================ ЛОГИ / НАКАЗАНИЯ ============================
async def get_log_channel(guild, kind):
    cid = cfg["log_channels"].get(kind)
    if not cid:
        return None
    channel = (guild.get_channel(cid) if guild else None) or bot.get_channel(cid)
    if channel is None:
        try:
            channel = await bot.fetch_channel(cid)
        except Exception as e:
            log.warning("Канал логов «%s» (%s) недоступен: %s", LOG_NAMES.get(kind, kind), cid, e)
            return None
    return channel


async def send_embed(guild, kind, embed):
    channel = await get_log_channel(guild, kind)
    if channel is None:
        return
    try:
        await channel.send(embed=embed)
    except Exception as e:
        log.warning("Не удалось отправить лог «%s» в канал %s: %s",
                    LOG_NAMES.get(kind, kind), channel.id, e)


def channel_problems(channel):
    """Каких прав не хватает боту в канале логов."""
    me = channel.guild.me
    perms = channel.permissions_for(me)
    missing = []
    if not perms.view_channel:
        missing.append("Просматривать канал")
    if not perms.send_messages:
        missing.append("Отправлять сообщения")
    if not perms.embed_links:
        missing.append("Встраивать ссылки")
    return missing


async def check_log_channels(guild):
    """Возвращает список строк с результатом проверки каждого канала логов."""
    lines = []
    for kind, name in LOG_NAMES.items():
        cid = cfg["log_channels"].get(kind)
        channel = await get_log_channel(guild, kind)
        if channel is None:
            lines.append(f"❌ **{name}**: канал `{cid}` не найден или недоступен боту")
            continue
        if not hasattr(channel, "send") or isinstance(channel, discord.ForumChannel):
            lines.append(f"❌ **{name}**: {channel.mention} — в этот тип канала нельзя писать")
            continue
        missing = channel_problems(channel)
        if missing:
            lines.append(f"❌ **{name}**: {channel.mention} — нет прав: {', '.join(missing)}")
        else:
            lines.append(f"✅ **{name}**: {channel.mention}")
    if guild and not guild.me.guild_permissions.manage_guild:
        lines.append("⚠️ Нет права **«Управлять сервером»** — бот не видит приглашения вашего сервера "
                     "и при большом потоке ссылок может ошибиться")
    if guild and not guild.me.guild_permissions.view_audit_log:
        lines.append("❌ Нет права **«Просмотр журнала аудита»** — баны, кики, тайм-ауты, муты, "
                     "каналы и роли логироваться не будут")
    return lines


def add_message_fields(embed, message):
    """Добавляет в лог текст удалённого сообщения, канал и вложения."""
    content = message.content or ""
    if len(content) > 1000:
        content = content[:1000] + "…"
    embed.add_field(name="Канал", value=f"{message.channel.mention}", inline=True)
    embed.add_field(name="Удалённое сообщение",
                    value=f"```{content.replace('`', 'ˋ')}```" if content else "*(без текста)*",
                    inline=False)
    if message.attachments:
        files = "\n".join(a.filename for a in message.attachments)[:1000]
        embed.add_field(name="Вложения", value=files, inline=False)


async def send_log(guild, title, member, rule_key, text, color, message=None, kind="automod"):
    embed = discord.Embed(title=title, description=text, color=color,
                          timestamp=discord.utils.utcnow())
    embed.add_field(name="Пользователь", value=f"{member.mention} (`{member.id}`)", inline=True)
    if rule_key:
        embed.add_field(name="Правило", value=RULE_NAMES.get(rule_key, rule_key), inline=True)
    if message is not None:
        add_message_fields(embed, message)
    await send_embed(guild, kind, embed)


async def dm(member, title, text, color=discord.Color.orange()):
    try:
        await member.send(embed=discord.Embed(
            title=title, description=text, color=color,
            timestamp=discord.utils.utcnow()).set_footer(text=f"Сервер: {member.guild.name}"))
    except Exception:
        pass


async def do_ban(member, reason, rule_key, message=None):
    key = (member.guild.id, member.id)
    if time.time() - recent_bans.get(key, 0) < 60:
        return  # уже банится — остальные сообщения просто удаляются
    recent_bans[key] = time.time()
    try:
        await asyncio.wait_for(dm(member, "Вы забанены", f"Причина: {reason}", discord.Color.red()), 3)
    except Exception:
        pass
    try:
        await member.guild.ban(member, reason=reason, delete_message_days=0)
        await send_log(member.guild, "🔨 Бан (автомодерация)", member, rule_key, f"Причина: {reason}",
                       discord.Color.red(), message, kind="ban")
    except Exception as e:
        await send_log(member.guild, "⚠️ Не удалось забанить", member, rule_key,
                       f"Причина: {reason}\nОшибка: `{e}`", discord.Color.dark_red(), message,
                       kind="ban")


async def do_strip(member, reason, rule_key, message=None):
    await dm(member, "С вас сняты все роли", f"Причина: {reason}", discord.Color.red())
    try:
        top = member.guild.me.top_role
        # снимаем только те роли, которые бот может снять (ниже его роли, не служебные)
        removable = [r for r in member.roles if not (r.is_default() or r.managed) and r < top]
        skipped = [r for r in member.roles if not (r.is_default() or r.managed) and r >= top]
        if removable:
            await member.remove_roles(*removable, reason=reason)
        # объединяем с ранее снятыми ролями, чтобы /amnesty вернул всё
        saved = cfg["stripped"].get(str(member.id), [])
        cfg["stripped"][str(member.id)] = saved + [r.id for r in removable if r.id not in saved]
        save()
        text = f"Причина: {reason}\nСнято ролей: **{len(removable)}**"
        if skipped:
            text += ("\n⚠️ Не удалось снять (выше роли бота): "
                     + ", ".join(r.mention for r in skipped)[:900])
        await send_log(member.guild, "🧹 Снятие всех ролей", member, rule_key,
                       text, discord.Color.purple(), message)
    except Exception as e:
        await send_log(member.guild, "⚠️ Не удалось снять роли", member, rule_key,
                       f"Причина: {reason}\nОшибка: `{e}`", discord.Color.dark_red(), message)


async def add_warns(member, amount, reason, rule_key, message=None):
    uid = str(member.id)
    current = len(active_warns(uid))
    total = current + amount
    limit = cfg["max_warns"]
    await send_log(member.guild, "⚠️ Предупреждение", member, rule_key,
                   f"Причина: {reason}\nВыдано: **{amount}**, всего: **{min(total, limit)}/{limit}**"
                   if total < limit else
                   f"Причина: {reason}\nВыдано: **{amount}**, достигнут лимит **{limit}**",
                   discord.Color.orange(), message)
    if total >= limit:
        cfg["warns"].pop(uid, None)
        save()
        full = f"{reason} (лимит предупреждений: {limit})"
        if cfg["limit_action"] == "ban":
            await do_ban(member, full, rule_key)
        else:
            await do_strip(member, full, rule_key)
    else:
        cfg["warns"][uid] = cfg["warns"].get(uid, []) + [time.time()] * amount
        save()
        await dm(member, "⚠️ Предупреждение",
                 f"Причина: {reason}\nВаши предупреждения: **{total}/{limit}**\n"
                 f"При достижении лимита вы получите наказание "
                 f"({LIMIT_ACTION_NAMES[cfg['limit_action']].lower()}).")


async def punish(member, rule_key, reason, message=None):
    rule = cfg["rules"][rule_key]
    action = rule["action"]
    if action == "delete":
        await send_log(member.guild, "🗑️ Сообщение удалено", member, rule_key, f"Причина: {reason}",
                       discord.Color.light_grey(), message)
    elif action == "warn":
        await add_warns(member, max(1, rule.get("warns", 1)), reason, rule_key, message)
    elif action == "ban":
        await do_ban(member, reason, rule_key, message)
    elif action == "strip":
        await do_strip(member, reason, rule_key, message)


# ============================ ПРОВЕРКИ ============================
async def refresh_own_invites(guild, force=False):
    """Загружает список приглашений нашего сервера. Нужно право «Управлять сервером».
    Возвращает True, если список есть."""
    if not force and time.time() - own_invites_time.get(guild.id, 0) < 10:
        return guild.id in own_invites
    own_invites_time[guild.id] = time.time()
    try:
        codes = {inv.code.lower() for inv in await guild.invites()}
    except Exception as e:
        if force:
            log.warning("Не удалось получить приглашения сервера %s (нужно право «Управлять сервером»): %s",
                        guild.name, e)
        return guild.id in own_invites
    if guild.vanity_url_code:
        codes.add(guild.vanity_url_code.lower())
    own_invites[guild.id] = codes
    return True


async def is_own_invite(guild, code):
    """True — ссылка ведёт на наш сервер. Всё остальное (чужие, просроченные,
    непроверяемые ссылки) считается рекламой."""
    low = code.lower()
    if guild.vanity_url_code and low == guild.vanity_url_code.lower():
        return True
    if low in own_invites.get(guild.id, set()):
        return True
    # возможно, приглашение только что создали — обновляем список (не чаще раза в 10 сек.)
    if await refresh_own_invites(guild):
        return low in own_invites.get(guild.id, set())
    # запасной вариант, если у бота нет права «Управлять сервером»: спрашиваем Discord
    cached = invite_cache.get(code)
    if cached and time.time() - cached[0] < 600:
        return cached[1] == guild.id
    try:
        inv = await bot.fetch_invite(code, with_counts=False)  # регистр кода важен!
        gid = inv.guild.id if inv.guild else None
    except Exception:
        gid = None
    invite_cache[code] = (time.time(), gid)
    return gid == guild.id


@bot.event
async def on_invite_create(invite):
    if invite.guild:
        own_invites.setdefault(invite.guild.id, set()).add(invite.code.lower())


@bot.event
async def on_invite_delete(invite):
    if invite.guild and invite.guild.id in own_invites:
        own_invites[invite.guild.id].discard(invite.code.lower())


async def detect(message, check_dup):
    """Возвращает (rule_key, причина) или None."""
    rules = cfg["rules"]
    content = message.content or ""

    if rules["invite"]["enabled"]:
        for code in INVITE_RE.findall(content):
            if not await is_own_invite(message.guild, code):
                return "invite", "Ссылка-приглашение на другой Discord-сервер"

    if rules["phishing"]["enabled"]:
        if PHISH_RE.search(content) or PHISH_DOMAINS_RE.search(content):
            return "phishing", "Скам / фишинг / ссылка-перенаправление"

    if rules["shortlink"]["enabled"] and SHORT_RE.search(content):
        return "shortlink", "Короткая или опасная ссылка"

    if rules["crypto"]["enabled"] and CRYPTO_RE.search(content):
        return "crypto", "Крипто-реклама"

    if rules["mentions"]["enabled"]:
        limit = rules["mentions"]["limit"]
        count = len(set(message.raw_mentions)) + len(set(message.raw_role_mentions))
        if "@everyone" in content or "@here" in content:
            count += limit
        if count >= limit:
            return "mentions", f"Массовые упоминания ({count})"

    if check_dup and rules["duplicate"]["enabled"]:
        norm = content.strip().lower()
        if norm:
            r = rules["duplicate"]
            now = time.time()
            key = (message.guild.id, message.author.id)
            hist = history[key]
            while hist and now - hist[0][1] > r["window"]:
                hist.popleft()
            hist.append((norm, now, message.channel.id, message.id))
            same = [e for e in hist if e[0] == norm]
            if len(same) >= r["count"]:
                for e in same:
                    if e[3] == message.id:
                        continue
                    try:
                        await message.guild.get_channel_or_thread(e[2]).get_partial_message(e[3]).delete()
                    except Exception:
                        pass
                history[key] = deque(e for e in hist if e[0] != norm)
                return "duplicate", f"Одинаковые сообщения ({len(same)} за {r['window']} сек.)"
    return None


async def check_message(message, check_dup=True):
    if not message.guild or message.author.bot or not isinstance(message.author, discord.Member):
        return
    member = message.author
    if member.id in cfg["whitelist"] or member.guild_permissions.administrator:
        return
    result = await detect(message, check_dup)
    if not result:
        return
    key, reason = result
    try:
        await message.delete()
    except Exception:
        pass
    await punish(member, key, reason, message)


@bot.event
async def on_message(message):
    try:
        await check_message(message)
    except Exception:
        log.exception("Ошибка при проверке сообщения")


@bot.event
async def on_message_edit(before, after):
    if before.content == after.content:
        return
    try:
        await check_message(after, check_dup=False)
    except Exception:
        log.exception("Ошибка при проверке изменённого сообщения")


# ============================ ЛОГИ МОДЕРАЦИИ ============================
# Тайм-ауты, баны, разбаны, кики и отключения/перемещения из голосовых каналов,
# которые делают модераторы. Берётся из журнала аудита (боту нужно право «Просмотр журнала аудита»).
voice_audit_counts: dict[int, int] = {}   # id записи журнала -> сколько раз уже учли
voice_audit_lock = asyncio.Lock()


def fmt_duration(seconds):
    seconds = max(0, int(seconds))
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    parts = []
    if days:
        parts.append(f"{days} д.")
    if hours:
        parts.append(f"{hours} ч.")
    if minutes or not parts:
        parts.append(f"{minutes} мин.")
    return " ".join(parts)


def fmt_user(user, user_id=None):
    uid = user.id if user is not None else user_id
    return f"<@{uid}> (`{uid}`)" if uid else "неизвестно"


async def send_mod_log(guild, kind, title, target_id, moderator, reason, color, extra=None,
                       moderator_id=None):
    embed = discord.Embed(title=title, color=color, timestamp=discord.utils.utcnow())
    embed.add_field(name="Пользователь",
                    value=f"<@{target_id}> (`{target_id}`)" if target_id else "неизвестно", inline=True)
    embed.add_field(name="Модератор", value=fmt_user(moderator, moderator_id), inline=True)
    for name, value in (extra or []):
        embed.add_field(name=name, value=str(value)[:1024], inline=False)
    if reason is not False:
        embed.add_field(name="Причина", value=(reason or "не указана")[:1000], inline=False)
    await send_embed(guild, kind, embed)


# ---------- изменения каналов и ролей ----------
DIFF_NAMES = {
    "name": "Название", "topic": "Тема", "nsfw": "NSFW", "slowmode_delay": "Медленный режим (сек.)",
    "bitrate": "Битрейт", "user_limit": "Лимит участников", "position": "Позиция", "type": "Тип",
    "rtc_region": "Регион", "video_quality_mode": "Качество видео",
    "default_auto_archive_duration": "Автоархивация веток (мин.)", "flags": "Флаги",
    "available_tags": "Теги", "default_reaction_emoji": "Реакция по умолчанию",
    "colour": "Цвет", "color": "Цвет", "permissions": "Права", "hoist": "Показывать отдельно",
    "mentionable": "Можно упоминать", "icon": "Иконка", "unicode_emoji": "Эмодзи",
    "allow": "Разрешено", "deny": "Запрещено", "overwrites": "Права доступа к каналу",
}
DIFF_SKIP = {"id", "permission_overwrites"}


def perm_list(perms):
    names = [n for n, v in perms if v]
    return ", ".join(f"`{n}`" for n in names) if names else "—"


def fmt_value(v):
    if v is None or v == "":
        return "—"
    if isinstance(v, bool):
        return "да" if v else "нет"
    if isinstance(v, discord.Colour):
        return str(v)
    if isinstance(v, discord.Permissions):
        return perm_list(v)
    if isinstance(v, (list, tuple)):
        return f"{len(v)} шт."
    if hasattr(v, "mention"):
        return v.mention
    return str(v)


def diff_fields(entry, created=False, deleted=False):
    """Строит поля эмбеда по изменениям из журнала аудита."""
    before = dict(iter(entry.before))
    after = dict(iter(entry.after))
    fields = []
    for key in list(after.keys()) + [k for k in before if k not in after]:
        if key in DIFF_SKIP:
            continue
        name = DIFF_NAMES.get(key, key)
        b, a = before.get(key), after.get(key)
        if isinstance(a, discord.Permissions) and isinstance(b, discord.Permissions) \
                and not created and not deleted:
            added = [n for n, v in a if v and not getattr(b, n)]
            removed = [n for n, v in a if not v and getattr(b, n)]
            text = []
            if added:
                text.append("➕ " + ", ".join(f"`{n}`" for n in added))
            if removed:
                text.append("➖ " + ", ".join(f"`{n}`" for n in removed))
            if text:
                fields.append((name, "\n".join(text)))
        elif created:
            fields.append((name, fmt_value(a)))
        elif deleted:
            fields.append((name, fmt_value(b)))
        elif b != a:
            fields.append((name, f"{fmt_value(b)} → {fmt_value(a)}"))
    return fields[:20]


async def log_server_change(entry, title, color, subject, created=False, deleted=False, extra=None):
    embed = discord.Embed(title=title, color=color, timestamp=discord.utils.utcnow())
    embed.add_field(name="Объект", value=subject, inline=True)
    embed.add_field(name="Кто", value=fmt_user(entry.user, entry.user_id), inline=True)
    for name, value in (extra or []):
        embed.add_field(name=name, value=str(value)[:1024], inline=False)
    for name, value in diff_fields(entry, created, deleted):
        value = str(value)[:1000]
        if len(embed) + len(name) + len(value) > 5500:  # лимит Discord — 6000 символов на эмбед
            embed.add_field(name="…", value="Остальные изменения не поместились", inline=False)
            break
        embed.add_field(name=name, value=value, inline=False)
    if entry.reason:
        embed.add_field(name="Причина", value=entry.reason[:1000], inline=False)
    await send_embed(entry.guild, "server", embed)


def channel_subject(entry, deleted=False):
    ch = entry.target
    cid = getattr(ch, "id", None)
    if deleted or not hasattr(ch, "mention") or isinstance(ch, discord.Object):
        name = getattr(entry.before, "name", None) or getattr(entry.after, "name", None) \
            or getattr(ch, "name", None)
        return f"#{name} (`{cid}`)" if name else f"`{cid}`"
    return f"{ch.mention} (`{cid}`)"


def role_subject(entry, deleted=False):
    role = entry.target
    rid = getattr(role, "id", None)
    if deleted or not isinstance(role, discord.Role):
        name = getattr(entry.before, "name", None) or getattr(entry.after, "name", None)
        return f"@{name} (`{rid}`)" if name else f"`{rid}`"
    return f"{role.mention} (`{rid}`)"


def overwrite_target(entry):
    t = entry.extra
    if isinstance(t, discord.Role):
        return f"роль {t.mention}"
    if isinstance(t, (discord.Member, discord.User)):
        return f"участник {t.mention}"
    tid = getattr(t, "id", None)
    return f"`{tid}`" if tid else "неизвестно"


_MISSING = object()


@bot.event
async def on_audit_log_entry_create(entry):
    try:
        await handle_audit_entry(entry)
    except Exception:
        log.exception("Ошибка при обработке журнала аудита")


async def handle_audit_entry(entry):
    guild = entry.guild
    A = discord.AuditLogAction
    moderator = entry.user
    target_id = getattr(entry.target, "id", None)
    by_bot = bot.user is not None and entry.user_id == bot.user.id

    mid = entry.user_id

    # ---------- баны и кики ----------
    if entry.action == A.ban:
        if by_bot:
            return  # свои баны бот уже записал в лог с причиной и сообщением
        await send_mod_log(guild, "ban", "🔨 Бан", target_id, moderator, entry.reason,
                           discord.Color.red(), moderator_id=mid)

    elif entry.action == A.unban:
        await send_mod_log(guild, "ban", "🔓 Разбан", target_id, moderator, entry.reason,
                           discord.Color.green(), moderator_id=mid)

    elif entry.action == A.kick:
        await send_mod_log(guild, "ban", "👢 Кик (выгнан с сервера)", target_id, moderator,
                           entry.reason, discord.Color.orange(), moderator_id=mid)

    # ---------- тайм-ауты и муты ----------
    elif entry.action == A.member_update:
        b_to = getattr(entry.before, "timed_out_until", _MISSING)
        a_to = getattr(entry.after, "timed_out_until", _MISSING)
        if a_to is not _MISSING and b_to != a_to:
            if a_to and a_to > discord.utils.utcnow():
                until = int(a_to.timestamp())
                extra = [("Длительность", fmt_duration((a_to - entry.created_at).total_seconds())),
                         ("До", f"<t:{until}:f> (<t:{until}:R>)")]
                await send_mod_log(guild, "timeout", "⏳ Тайм-аут", target_id, moderator,
                                   entry.reason, discord.Color.dark_orange(), extra, moderator_id=mid)
            else:
                await send_mod_log(guild, "timeout", "✅ Тайм-аут снят", target_id, moderator,
                                   entry.reason, discord.Color.green(), moderator_id=mid)

        voice_ch = None
        member = guild.get_member(target_id) if target_id else None
        if member and member.voice and member.voice.channel:
            voice_ch = [("Канал", member.voice.channel.mention)]
        a_mute = getattr(entry.after, "mute", _MISSING)
        if a_mute is not _MISSING and getattr(entry.before, "mute", None) != a_mute:
            await send_mod_log(guild, "voice",
                               "🔇 Мут в голосовом (микрофон)" if a_mute else "🎙️ Мут снят (микрофон)",
                               target_id, moderator, entry.reason,
                               discord.Color.dark_orange() if a_mute else discord.Color.green(),
                               voice_ch, moderator_id=mid)
        a_deaf = getattr(entry.after, "deaf", _MISSING)
        if a_deaf is not _MISSING and getattr(entry.before, "deaf", None) != a_deaf:
            await send_mod_log(guild, "voice",
                               "🔕 Заглушён в голосовом (звук)" if a_deaf else "🔔 Заглушение снято (звук)",
                               target_id, moderator, entry.reason,
                               discord.Color.dark_orange() if a_deaf else discord.Color.green(),
                               voice_ch, moderator_id=mid)

    # ---------- каналы ----------
    elif entry.action == A.channel_create:
        await log_server_change(entry, "📁 Канал создан", discord.Color.green(),
                                channel_subject(entry), created=True)
    elif entry.action == A.channel_update:
        await log_server_change(entry, "✏️ Канал изменён", discord.Color.blue(),
                                channel_subject(entry))
    elif entry.action == A.channel_delete:
        await log_server_change(entry, "🗑️ Канал удалён", discord.Color.red(),
                                channel_subject(entry, deleted=True), deleted=True)
    elif entry.action in (A.overwrite_create, A.overwrite_update, A.overwrite_delete):
        title = {A.overwrite_create: "🔐 Права канала добавлены",
                 A.overwrite_update: "🔐 Права канала изменены",
                 A.overwrite_delete: "🔐 Права канала удалены"}[entry.action]
        await log_server_change(entry, title, discord.Color.blue(), channel_subject(entry),
                                created=entry.action == A.overwrite_create,
                                deleted=entry.action == A.overwrite_delete,
                                extra=[("Для кого", overwrite_target(entry))])

    # ---------- роли ----------
    elif entry.action == A.role_create:
        await log_server_change(entry, "🏷️ Роль создана", discord.Color.green(),
                                role_subject(entry), created=True)
    elif entry.action == A.role_update:
        await log_server_change(entry, "✏️ Роль изменена", discord.Color.blue(), role_subject(entry))
    elif entry.action == A.role_delete:
        await log_server_change(entry, "🗑️ Роль удалена", discord.Color.red(),
                                role_subject(entry, deleted=True), deleted=True)


# ============================ ЗАХОДЫ НА СЕРВЕР ============================
@bot.event
async def on_member_join(member):
    try:
        created = int(member.created_at.timestamp())
        age_days = (discord.utils.utcnow() - member.created_at).days
        embed = discord.Embed(title="📥 Участник зашёл на сервер", color=discord.Color.green(),
                              timestamp=discord.utils.utcnow())
        embed.set_thumbnail(url=member.display_avatar.url)
        embed.add_field(name="Пользователь", value=f"{member.mention} (`{member.id}`)", inline=True)
        embed.add_field(name="Имя", value=str(member), inline=True)
        embed.add_field(name="Аккаунт создан", value=f"<t:{created}:f> (<t:{created}:R>)", inline=False)
        embed.add_field(name="Участников на сервере", value=str(member.guild.member_count), inline=True)
        if member.bot:
            embed.add_field(name="Тип", value="🤖 Бот", inline=True)
        if age_days < 7:
            embed.add_field(name="⚠️ Внимание", value=f"Новый аккаунт: ему {age_days} дн.", inline=False)
            embed.color = discord.Color.orange()
        await send_embed(member.guild, "join", embed)
    except Exception:
        log.exception("Ошибка при логировании захода")


@bot.event
async def on_voice_state_update(member, before, after):
    """Discord не присылает событие «модератор отключил/переместил участника», поэтому при выходе
    из голосового канала бот смотрит, не увеличился ли счётчик в журнале аудита."""
    if before.channel is None or before.channel == after.channel:
        return
    action = (discord.AuditLogAction.member_disconnect if after.channel is None
              else discord.AuditLogAction.member_move)
    try:
        await asyncio.sleep(1.5)  # журнал аудита обновляется с небольшой задержкой
        async with voice_audit_lock:
            found = None
            now = discord.utils.utcnow()
            async for entry in member.guild.audit_logs(limit=5, action=action):
                count = getattr(entry.extra, "count", 1) or 1
                seen = voice_audit_counts.get(entry.id)
                voice_audit_counts[entry.id] = count
                if found:
                    continue
                if action == discord.AuditLogAction.member_move:
                    ch = getattr(entry.extra, "channel", None)
                    if ch is not None and after.channel is not None and ch.id != after.channel.id:
                        continue
                if seen is None:
                    # новая запись: учитываем, только если она свежая (не старая после перезапуска)
                    if (now - entry.created_at).total_seconds() < 15:
                        found = entry
                elif count > seen:
                    found = entry
        if found is None:
            return  # участник вышел или перешёл сам
        if after.channel is None:
            await send_mod_log(member.guild, "voice", "📴 Отключён от голосового канала", member.id,
                               found.user, False, discord.Color.orange(),
                               [("Канал", before.channel.mention)], moderator_id=found.user_id)
        else:
            await send_mod_log(member.guild, "move", "🔀 Перемещён в другой голосовой канал", member.id,
                               found.user, False, discord.Color.blue(),
                               [("Откуда", before.channel.mention), ("Куда", after.channel.mention)],
                               moderator_id=found.user_id)
    except discord.Forbidden:
        log.warning("Нет права «Просмотр журнала аудита» — отключения из голосовых не логируются")
    except Exception:
        log.exception("Ошибка при логировании голосовых каналов")


# ============================ ПАНЕЛЬ: ЭМБЕДЫ ============================
def on_off(v):
    return "🟢 Вкл" if v else "🔴 Выкл"


def main_embed():
    e = discord.Embed(title="🛡️ Панель автомодерации",
                      description="Выберите правило для настройки.", color=discord.Color.blurple())
    for k, name in RULE_NAMES.items():
        r = cfg["rules"][k]
        act = ACTION_NAMES[r["action"]]
        if r["action"] == "warn":
            act += f" (x{r['warns']})"
        e.add_field(name=name, value=f"{on_off(r['enabled'])}\n{act}", inline=True)
    e.add_field(name="Общие",
                value=f"Лимит предупреждений: **{cfg['max_warns']}**\n"
                      f"Предупреждения сгорают через: **{ttl_text()}**\n"
                      f"При лимите: **{LIMIT_ACTION_NAMES[cfg['limit_action']]}**\n"
                      f"В белом списке: **{len(cfg['whitelist'])}**", inline=False)
    return e


def rule_embed(key):
    r = cfg["rules"][key]
    e = discord.Embed(title=RULE_NAMES[key], color=discord.Color.blurple())
    e.add_field(name="Статус", value=on_off(r["enabled"]))
    e.add_field(name="Действие", value=ACTION_NAMES[r["action"]])
    e.add_field(name="Предупреждений за нарушение", value=str(r["warns"]))
    if key == "mentions":
        e.add_field(name="Лимит упоминаний", value=str(r["limit"]))
    if key == "duplicate":
        e.add_field(name="Повторов для срабатывания", value=str(r["count"]))
        e.add_field(name="Окно времени (сек.)", value=str(r["window"]))
    e.set_footer(text="Предупреждения учитываются только при действии «Выдать предупреждение».")
    return e


def general_embed():
    e = discord.Embed(title="⚙️ Общие настройки", color=discord.Color.blurple())
    e.add_field(name="Лимит предупреждений", value=str(cfg["max_warns"]))
    e.add_field(name="Наказание при лимите", value=LIMIT_ACTION_NAMES[cfg["limit_action"]])
    e.add_field(name="Предупреждения сгорают через", value=ttl_text())
    return e


def logs_embed(kind=None):
    e = discord.Embed(title="📜 Каналы логов",
                      description="Выберите тип лога, затем канал, куда его отправлять.\n"
                                  "Кнопка «Проверить» покажет, каких прав не хватает боту.",
                      color=discord.Color.blurple())
    for k, n in LOG_NAMES.items():
        cid = cfg["log_channels"].get(k)
        mark = "👉 " if k == kind else ""
        e.add_field(name=f"{mark}{n}", value=f"<#{cid}>" if cid else "не задан", inline=True)
    return e


def whitelist_embed():
    ids = cfg["whitelist"]
    text = "\n".join(f"<@{i}> (`{i}`)" for i in ids) if ids else "Список пуст."
    e = discord.Embed(title="📋 Белый список", description=text[:4000], color=discord.Color.green())
    e.set_footer(text="Выберите пользователя: если он в списке — будет удалён, если нет — добавлен.")
    return e


# ============================ ПАНЕЛЬ: КОМПОНЕНТЫ ============================
class BaseView(discord.ui.View):
    def __init__(self):
        super().__init__(timeout=600)

    async def interaction_check(self, interaction):
        if is_admin(interaction.user):
            return True
        await interaction.response.send_message("У вас нет доступа к панели.", ephemeral=True)
        return False


class NumModal(discord.ui.Modal):
    def __init__(self, title, items, target, build):
        super().__init__(title=title)
        self.items = items
        self.target = target
        self.build = build
        self.inputs = {}
        for field, label, cur, lo, hi in items:
            ti = discord.ui.TextInput(label=f"{label} ({lo}-{hi})"[:45], default=str(cur), max_length=6)
            self.inputs[field] = ti
            self.add_item(ti)

    async def on_submit(self, interaction):
        vals = {}
        for field, label, cur, lo, hi in self.items:
            t = self.inputs[field].value.strip()
            if not t.isdigit() or not lo <= int(t) <= hi:
                return await interaction.response.send_message(
                    f"Неверное значение «{label}». Допустимо: {lo}-{hi}.", ephemeral=True)
            vals[field] = int(t)
        self.target.update(vals)
        save()
        embed, view = self.build()
        await interaction.response.edit_message(embed=embed, view=view)


def main_page():
    return main_embed(), MainView()


def rule_page(key):
    return rule_embed(key), RuleView(key)


def general_page():
    return general_embed(), GeneralView()


def whitelist_page():
    return whitelist_embed(), WhitelistView()


def logs_page(kind=None):
    return logs_embed(kind), LogsView(kind)


async def go(interaction, page):
    embed, view = page
    await interaction.response.edit_message(embed=embed, view=view)


class MainView(BaseView):
    @discord.ui.select(
        placeholder="Выберите правило для настройки…",
        options=[discord.SelectOption(label=n[:100], value=k) for k, n in RULE_NAMES.items()],
    )
    async def pick(self, interaction, select):
        await go(interaction, rule_page(select.values[0]))

    @discord.ui.button(label="Белый список", style=discord.ButtonStyle.success, emoji="📋")
    async def wl(self, interaction, button):
        await go(interaction, whitelist_page())

    @discord.ui.button(label="Общие настройки", style=discord.ButtonStyle.primary, emoji="⚙️")
    async def general(self, interaction, button):
        await go(interaction, general_page())

    @discord.ui.button(label="Каналы логов", style=discord.ButtonStyle.secondary, emoji="📜")
    async def logs(self, interaction, button):
        await go(interaction, logs_page())


class ActionSelect(discord.ui.Select):
    def __init__(self, key):
        self.key = key
        cur = cfg["rules"][key]["action"]
        super().__init__(
            placeholder="Действие при нарушении",
            options=[discord.SelectOption(label=n, value=a, default=(a == cur))
                     for a, n in ACTION_NAMES.items()],
        )

    async def callback(self, interaction):
        cfg["rules"][self.key]["action"] = self.values[0]
        save()
        await go(interaction, rule_page(self.key))


class RuleView(BaseView):
    def __init__(self, key):
        super().__init__()
        self.key = key
        self.add_item(ActionSelect(key))
        self.toggle.label = "Выключить" if cfg["rules"][key]["enabled"] else "Включить"
        self.toggle.style = (discord.ButtonStyle.danger if cfg["rules"][key]["enabled"]
                             else discord.ButtonStyle.success)
        if key not in ("mentions", "duplicate"):
            self.remove_item(self.params)

    @discord.ui.button(label="Вкл/Выкл", style=discord.ButtonStyle.success, row=1)
    async def toggle(self, interaction, button):
        r = cfg["rules"][self.key]
        r["enabled"] = not r["enabled"]
        save()
        await go(interaction, rule_page(self.key))

    @discord.ui.button(label="Кол-во предупреждений", style=discord.ButtonStyle.primary, row=1)
    async def warns(self, interaction, button):
        r = cfg["rules"][self.key]
        await interaction.response.send_modal(NumModal(
            "Предупреждения за нарушение",
            [("warns", "Предупреждений", r["warns"], 1, 20)],
            r, lambda: rule_page(self.key)))

    @discord.ui.button(label="Параметры", style=discord.ButtonStyle.secondary, row=1)
    async def params(self, interaction, button):
        r = cfg["rules"][self.key]
        if self.key == "mentions":
            items = [("limit", "Лимит упоминаний", r["limit"], 2, 50)]
        else:
            items = [("count", "Повторов", r["count"], 2, 20),
                     ("window", "Окно времени, сек.", r["window"], 5, 3600)]
        await interaction.response.send_modal(
            NumModal("Параметры правила", items, r, lambda: rule_page(self.key)))

    @discord.ui.button(label="Назад", style=discord.ButtonStyle.secondary, emoji="↩️", row=1)
    async def back(self, interaction, button):
        await go(interaction, main_page())


class LimitActionSelect(discord.ui.Select):
    def __init__(self):
        super().__init__(
            placeholder="Наказание при достижении лимита",
            options=[discord.SelectOption(label=n, value=a, default=(a == cfg["limit_action"]))
                     for a, n in LIMIT_ACTION_NAMES.items()],
        )

    async def callback(self, interaction):
        cfg["limit_action"] = self.values[0]
        save()
        await go(interaction, general_page())


class GeneralView(BaseView):
    def __init__(self):
        super().__init__()
        self.add_item(LimitActionSelect())

    @discord.ui.button(label="Срок действия предупреждений", style=discord.ButtonStyle.primary, row=1)
    async def ttl(self, interaction, button):
        await interaction.response.send_modal(NumModal(
            "Срок действия предупреждений",
            [("warn_ttl", "Часы, 0=никогда", cfg["warn_ttl"], 0, 8760)],
            cfg, general_page))

    @discord.ui.button(label="Лимит предупреждений", style=discord.ButtonStyle.primary, row=1)
    async def limit(self, interaction, button):
        await interaction.response.send_modal(NumModal(
            "Лимит предупреждений",
            [("max_warns", "Лимит", cfg["max_warns"], 1, 50)],
            cfg, general_page))

    @discord.ui.button(label="Назад", style=discord.ButtonStyle.secondary, emoji="↩️", row=1)
    async def back(self, interaction, button):
        await go(interaction, main_page())


class LogKindSelect(discord.ui.Select):
    def __init__(self, kind):
        super().__init__(
            placeholder="Какой лог настроить?",
            options=[discord.SelectOption(label=n, value=k, default=(k == kind))
                     for k, n in LOG_NAMES.items()],
            row=0,
        )

    async def callback(self, interaction):
        await go(interaction, logs_page(self.values[0]))


class LogChannelSelect(discord.ui.ChannelSelect):
    def __init__(self, kind):
        self.kind = kind
        super().__init__(
            placeholder=f"Канал для «{LOG_NAMES[kind]}»"[:100],
            channel_types=[discord.ChannelType.text, discord.ChannelType.news],
            min_values=1, max_values=1, row=1,
        )

    async def callback(self, interaction):
        cfg["log_channels"][self.kind] = self.values[0].id
        save()
        await go(interaction, logs_page(self.kind))


class LogsView(BaseView):
    def __init__(self, kind=None):
        super().__init__()
        self.add_item(LogKindSelect(kind))
        if kind:
            self.add_item(LogChannelSelect(kind))

    @discord.ui.button(label="Проверить", style=discord.ButtonStyle.success, emoji="🔎", row=2)
    async def test(self, interaction, button):
        await interaction.response.defer(ephemeral=True, thinking=True)
        lines = await check_log_channels(interaction.guild)
        await interaction.followup.send(
            embed=discord.Embed(title="🔎 Проверка каналов логов", description="\n".join(lines)[:4000],
                                color=discord.Color.blurple()),
            ephemeral=True)

    @discord.ui.button(label="Сбросить по умолчанию", style=discord.ButtonStyle.danger, row=2)
    async def reset(self, interaction, button):
        cfg["log_channels"] = dict(LOG_CHANNELS_DEFAULT)
        save()
        await go(interaction, logs_page())

    @discord.ui.button(label="Назад", style=discord.ButtonStyle.secondary, emoji="↩️", row=2)
    async def back(self, interaction, button):
        await go(interaction, main_page())


class WhitelistView(BaseView):
    @discord.ui.select(cls=discord.ui.UserSelect, placeholder="Добавить / убрать пользователя…",
                       min_values=1, max_values=10)
    async def users(self, interaction, select):
        for u in select.values:
            if u.id in cfg["whitelist"]:
                cfg["whitelist"].remove(u.id)
            else:
                cfg["whitelist"].append(u.id)
        save()
        await go(interaction, whitelist_page())

    @discord.ui.button(label="Назад", style=discord.ButtonStyle.secondary, emoji="↩️")
    async def back(self, interaction, button):
        await go(interaction, main_page())


# ============================ КОМАНДЫ ============================
async def deny(interaction):
    await interaction.response.send_message("У вас нет доступа к этой команде.", ephemeral=True)


@bot.tree.command(name="panel", description="Панель управления автомодерацией")
@app_commands.guild_only()
async def panel(interaction: discord.Interaction):
    if not is_admin(interaction.user):
        return await deny(interaction)
    embed, view = main_page()
    await interaction.response.send_message(embed=embed, view=view, ephemeral=True)


@bot.tree.command(name="warns", description="Показать предупреждения участника")
@app_commands.guild_only()
async def warns_cmd(interaction: discord.Interaction, user: discord.Member):
    if not is_admin(interaction.user):
        return await deny(interaction)
    n = len(active_warns(str(user.id)))
    await interaction.response.send_message(
        f"У {user.mention} предупреждений: **{n}/{cfg['max_warns']}**", ephemeral=True)


@bot.tree.command(name="clearwarns", description="Сбросить предупреждения участника")
@app_commands.guild_only()
async def clearwarns(interaction: discord.Interaction, user: discord.Member):
    if not is_admin(interaction.user):
        return await deny(interaction)
    cfg["warns"].pop(str(user.id), None)
    save()
    await interaction.response.send_message(f"Предупреждения {user.mention} сброшены.", ephemeral=True)
    await send_log(interaction.guild, "✅ Предупреждения сброшены", user, None,
                   f"Модератор: {interaction.user.mention}", discord.Color.green())


@bot.tree.command(name="amnesty", description="Амнистия: разбан, сброс предупреждений, возврат снятых ролей")
@app_commands.guild_only()
@app_commands.describe(user="Пользователь (можно указать ID забаненного)")
async def amnesty(interaction: discord.Interaction, user: discord.User):
    if not is_admin(interaction.user):
        return await deny(interaction)
    await interaction.response.defer(ephemeral=True)
    guild = interaction.guild
    done = []

    try:
        await guild.fetch_ban(user)
        await guild.unban(user, reason=f"Амнистия от {interaction.user}")
        done.append("разбан")
    except discord.NotFound:
        pass
    except Exception as e:
        done.append(f"разбан не удался ({e})")

    if cfg["warns"].pop(str(user.id), None):
        done.append("предупреждения сброшены")

    ids = cfg["stripped"].pop(str(user.id), [])
    member = guild.get_member(user.id)
    if ids and member:
        roles = [r for r in (guild.get_role(i) for i in ids)
                 if r and not r.managed and r < guild.me.top_role]
        try:
            if roles:
                await member.add_roles(*roles, reason=f"Амнистия от {interaction.user}")
                done.append(f"возвращено ролей: {len(roles)}")
        except Exception as e:
            done.append(f"роли вернуть не удалось ({e})")
    save()

    if not done:
        return await interaction.followup.send(
            f"У {user.mention} нет наказаний для снятия.", ephemeral=True)
    text = ", ".join(done)
    await interaction.followup.send(f"Амнистия для {user.mention}: {text}.", ephemeral=True)
    await send_log(guild, "🕊️ Амнистия", user, None,
                   f"Модератор: {interaction.user.mention}\nДействия: {text}",
                   discord.Color.green())
    if member:
        await dm(member, "🕊️ Амнистия", f"С вас сняты наказания: {text}.", discord.Color.green())


if __name__ == "__main__":
    if not TOKEN:
        raise SystemExit("Не найден токен. Укажите TOKEN в .env или в переменных окружения хостинга.")
    bot.run(TOKEN)
