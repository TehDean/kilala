-- Kilala: friend network map. All tables prefixed kilala_ so they sit safely
-- next to the other apps in Playground 1.

create extension if not exists pgcrypto with schema extensions;

-- ---------- tables ----------
create table public.kilala_people (
  id uuid primary key default gen_random_uuid(),
  name text not null check (length(trim(name)) between 1 and 60),
  groups text[] not null default '{}',
  user_id uuid unique references auth.users(id) on delete set null,
  email text,
  invite_token text not null unique default encode(extensions.gen_random_bytes(12), 'hex'),
  is_admin boolean not null default false,
  joined_at timestamptz,
  created_at timestamptz not null default now()
);

-- one row per pair, a < b
create table public.kilala_links (
  a uuid not null references public.kilala_people(id) on delete cascade,
  b uuid not null references public.kilala_people(id) on delete cascade,
  a_ok boolean,          -- what person a says (null = hasn't answered)
  b_ok boolean,          -- what person b says
  admin_ok boolean,      -- Dean's guess, used until people answer
  how_met text check (how_met is null or length(how_met) <= 120),
  introduced_by uuid references public.kilala_people(id) on delete set null,
  counted boolean not null default false,
  counted_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (a, b),
  check (a < b)
);
create index on public.kilala_links (b);
create index on public.kilala_links (introduced_by);

create table public.kilala_events (
  id uuid primary key default gen_random_uuid(),
  name text not null check (length(trim(name)) between 1 and 80),
  happened_on date not null default current_date,
  created_at timestamptz not null default now()
);

create table public.kilala_event_guests (
  event_id uuid not null references public.kilala_events(id) on delete cascade,
  person_id uuid not null references public.kilala_people(id) on delete cascade,
  primary key (event_id, person_id)
);
create index on public.kilala_event_guests (person_id);

create table public.kilala_event_intros (
  event_id uuid not null references public.kilala_events(id) on delete cascade,
  a uuid not null references public.kilala_people(id) on delete cascade,
  b uuid not null references public.kilala_people(id) on delete cascade,
  reason text,
  done boolean not null default false,
  primary key (event_id, a, b),
  check (a < b)
);
create index on public.kilala_event_intros (a);
create index on public.kilala_event_intros (b);

-- ---------- helpers ----------
create or replace function public.kilala_me() returns uuid
language sql stable security definer set search_path = '' as $$
  select id from public.kilala_people where user_id = auth.uid()
$$;

create or replace function public.kilala_is_admin() returns boolean
language sql stable security definer set search_path = '' as $$
  select coalesce((select is_admin from public.kilala_people where user_id = auth.uid()), false)
$$;

-- ---------- row security ----------
alter table public.kilala_people enable row level security;
alter table public.kilala_links enable row level security;
alter table public.kilala_events enable row level security;
alter table public.kilala_event_guests enable row level security;
alter table public.kilala_event_intros enable row level security;

-- members (anyone who claimed an invite) can see the network
create policy kilala_people_read on public.kilala_people for select to authenticated
  using ((select public.kilala_me()) is not null);
create policy kilala_links_read on public.kilala_links for select to authenticated
  using ((select public.kilala_me()) is not null);

-- only the admin manages people and events
create policy kilala_people_admin_ins on public.kilala_people for insert to authenticated
  with check ((select public.kilala_is_admin()) and is_admin = false and user_id is null);
create policy kilala_people_admin_upd on public.kilala_people for update to authenticated
  using ((select public.kilala_is_admin())) with check ((select public.kilala_is_admin()));
create policy kilala_people_admin_del on public.kilala_people for delete to authenticated
  using ((select public.kilala_is_admin()) and is_admin = false);

create policy kilala_events_admin on public.kilala_events for all to authenticated
  using ((select public.kilala_is_admin())) with check ((select public.kilala_is_admin()));
create policy kilala_guests_admin on public.kilala_event_guests for all to authenticated
  using ((select public.kilala_is_admin())) with check ((select public.kilala_is_admin()));
create policy kilala_intros_admin on public.kilala_event_intros for all to authenticated
  using ((select public.kilala_is_admin())) with check ((select public.kilala_is_admin()));

-- invite tokens and emails are never readable directly; admin uses kilala_invite_token()
revoke all on public.kilala_people from anon, authenticated;
grant select (id, name, groups, user_id, is_admin, joined_at, created_at) on public.kilala_people to authenticated;
grant insert (name, groups) on public.kilala_people to authenticated;
grant update (name, groups) on public.kilala_people to authenticated;
grant delete on public.kilala_people to authenticated;

revoke all on public.kilala_links from anon, authenticated;
grant select on public.kilala_links to authenticated;   -- writes go through functions below

revoke all on public.kilala_events, public.kilala_event_guests, public.kilala_event_intros from anon;

-- ---------- counting rule ----------
-- A link counts when nobody has said "no", and each side either said yes
-- or Dean vouched for it (admin_ok) while that person hasn't answered.
create or replace function public.kilala_recount(p_a uuid, p_b uuid) returns void
language plpgsql security definer set search_path = '' as $$
declare
  r public.kilala_links;
  now_counted boolean;
begin
  select * into r from public.kilala_links where a = p_a and b = p_b;
  if not found then return; end if;
  now_counted := coalesce(r.a_ok, r.admin_ok, false) and coalesce(r.b_ok, r.admin_ok, false);
  update public.kilala_links
     set counted = now_counted,
         counted_at = case when now_counted and not r.counted then now()
                           when now_counted then r.counted_at
                           else null end,
         updated_at = now()
   where a = p_a and b = p_b;
end $$;
revoke all on function public.kilala_recount(uuid, uuid) from public, anon, authenticated;

-- ---------- actions ----------
-- claim a personal invite link
create or replace function public.kilala_claim(p_token text) returns uuid
language plpgsql security definer set search_path = '' as $$
declare
  me uuid := public.kilala_me();
  pid uuid;
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  if me is not null then return me; end if;
  update public.kilala_people
     set user_id = auth.uid(),
         email = (select email from auth.users where id = auth.uid()),
         joined_at = now()
   where invite_token = p_token and user_id is null
   returning id into pid;
  if pid is null then raise exception 'invite link not valid or already used'; end if;
  return pid;
end $$;

-- a member says whether they know someone
create or replace function public.kilala_set_link(
  p_other uuid, p_knows boolean, p_how_met text default null, p_introduced_by uuid default null
) returns void
language plpgsql security definer set search_path = '' as $$
declare
  me uuid := public.kilala_me();
  am_admin boolean := public.kilala_is_admin();
  x uuid; y uuid;
begin
  if me is null then raise exception 'not a member'; end if;
  if p_other = me then raise exception 'that is you'; end if;
  if not exists (select 1 from public.kilala_people where id = p_other) then raise exception 'unknown person'; end if;
  if p_introduced_by in (me, p_other) then p_introduced_by := null; end if;
  x := least(me, p_other); y := greatest(me, p_other);
  insert into public.kilala_links (a, b) values (x, y) on conflict do nothing;
  update public.kilala_links set
    a_ok = case when a = me then p_knows else a_ok end,
    b_ok = case when b = me then p_knows else b_ok end,
    admin_ok = case when am_admin then p_knows else admin_ok end,  -- Dean's own answer also vouches for the other side
    how_met = coalesce(nullif(trim(p_how_met), ''), how_met),
    introduced_by = coalesce(p_introduced_by, introduced_by)
  where a = x and b = y;
  perform public.kilala_recount(x, y);
end $$;

-- admin records a guess (or an intro) between any two people
create or replace function public.kilala_admin_link(
  p1 uuid, p2 uuid, p_knows boolean, p_how_met text default null, p_introduced_by uuid default null
) returns void
language plpgsql security definer set search_path = '' as $$
declare
  me uuid := public.kilala_me();
  x uuid := least(p1, p2); y uuid := greatest(p1, p2);
begin
  if not public.kilala_is_admin() then raise exception 'admin only'; end if;
  if p1 = p2 then raise exception 'same person'; end if;
  if p_introduced_by in (p1, p2) then p_introduced_by := null; end if;
  insert into public.kilala_links (a, b) values (x, y) on conflict do nothing;
  update public.kilala_links set
    admin_ok = p_knows,
    a_ok = case when a = me then p_knows else a_ok end,
    b_ok = case when b = me then p_knows else b_ok end,
    how_met = coalesce(nullif(trim(p_how_met), ''), how_met),
    introduced_by = coalesce(p_introduced_by, introduced_by)
  where a = x and b = y;
  perform public.kilala_recount(x, y);
end $$;

-- admin fetches someone's personal invite token
create or replace function public.kilala_invite_token(p_person uuid) returns text
language plpgsql stable security definer set search_path = '' as $$
begin
  if not public.kilala_is_admin() then raise exception 'admin only'; end if;
  return (select invite_token from public.kilala_people where id = p_person);
end $$;

-- admin makes a fresh link (e.g. if one got forwarded); the old one stops working
create or replace function public.kilala_new_invite(p_person uuid) returns text
language plpgsql security definer set search_path = '' as $$
declare t text;
begin
  if not public.kilala_is_admin() then raise exception 'admin only'; end if;
  update public.kilala_people set invite_token = encode(extensions.gen_random_bytes(12), 'hex')
   where id = p_person and user_id is null returning invite_token into t;
  return t;
end $$;

revoke all on function public.kilala_claim(text), public.kilala_set_link(uuid, boolean, text, uuid),
  public.kilala_admin_link(uuid, uuid, boolean, text, uuid), public.kilala_invite_token(uuid),
  public.kilala_new_invite(uuid), public.kilala_me(), public.kilala_is_admin() from public, anon;
grant execute on function public.kilala_claim(text), public.kilala_set_link(uuid, boolean, text, uuid),
  public.kilala_admin_link(uuid, uuid, boolean, text, uuid), public.kilala_invite_token(uuid),
  public.kilala_new_invite(uuid), public.kilala_me(), public.kilala_is_admin() to authenticated;

-- Dean is the first person and the admin. He claims this row with his own invite link.
insert into public.kilala_people (name, is_admin) values ('Dean', true);

-- ---------- intro wish list (Dean only) ----------
create table public.kilala_wishes (
  a uuid not null references public.kilala_people(id) on delete cascade,
  b uuid not null references public.kilala_people(id) on delete cascade,
  reason text check (reason is null or length(reason) <= 120),
  created_at timestamptz not null default now(),
  primary key (a, b),
  check (a < b)
);
create index on public.kilala_wishes (b);
alter table public.kilala_wishes enable row level security;
create policy kilala_wishes_admin on public.kilala_wishes for all to authenticated
  using ((select public.kilala_is_admin())) with check ((select public.kilala_is_admin()));
revoke all on public.kilala_wishes from anon;
