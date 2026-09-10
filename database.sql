
-- Supabase Public Schema
-- Generated: 2026-09-10


-- Required extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto" WITH SCHEMA extensions;
CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA extensions;



-- 1. profiles


CREATE TABLE IF NOT EXISTS public.profiles (
    id uuid NOT NULL,
    email text NOT NULL UNIQUE,
    full_name text,
    avatar_url text,
    app_plan text DEFAULT 'free'::text,
    app_credits integer DEFAULT 10,
    updated_at timestamptz NOT NULL DEFAULT timezone('utc'::text, now()),
    webhook_url text,
    webhook_secret text,
    monthly_api_usage integer DEFAULT 0,
    api_plan text DEFAULT 'free'::text,

    CONSTRAINT profiles_pkey PRIMARY KEY (id),
    CONSTRAINT profiles_id_fkey
        FOREIGN KEY (id)
        REFERENCES auth.users(id)
);


-- 2. scans


CREATE TABLE IF NOT EXISTS public.scans (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    user_id text NOT NULL,
    input_type text NOT NULL,
    input_data text NOT NULL,
    risk_level text NOT NULL,
    ai_explanation text,
    scanned_at timestamptz DEFAULT now(),
    is_deleted boolean DEFAULT false,
    reason text,

    CONSTRAINT scans_pkey PRIMARY KEY (id)
);



-- 3. api_keys


CREATE TABLE IF NOT EXISTS public.api_keys (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    user_id uuid,
    name varchar DEFAULT 'Default Key'::varchar,
    key_prefix varchar NOT NULL,
    key_hash text NOT NULL UNIQUE,
    is_active boolean DEFAULT true,
    created_at timestamptz NOT NULL
        DEFAULT timezone('utc'::text, now()),

    CONSTRAINT api_keys_pkey PRIMARY KEY (id),
    CONSTRAINT api_keys_user_id_fkey
        FOREIGN KEY (user_id)
        REFERENCES public.profiles(id)
);



-- 4. api_logs


CREATE TABLE IF NOT EXISTS public.api_logs (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    user_id uuid,
    endpoint varchar NOT NULL,
    method varchar DEFAULT 'POST'::varchar,
    status_code integer NOT NULL,
    latency_ms integer NOT NULL,
    risk_level varchar,
    created_at timestamptz NOT NULL
        DEFAULT timezone('utc'::text, now()),
    end_user_id text DEFAULT 'anonymous'::text,

    CONSTRAINT api_logs_pkey PRIMARY KEY (id),
    CONSTRAINT api_logs_user_id_fkey
        FOREIGN KEY (user_id)
        REFERENCES public.profiles(id)
);



-- 5. support_tickets


CREATE TABLE IF NOT EXISTS public.support_tickets (
    id uuid NOT NULL DEFAULT gen_random_uuid(),
    name text NOT NULL,
    email text NOT NULL,
    message text NOT NULL,
    status text DEFAULT 'pending'::text,
    created_at timestamptz NOT NULL
        DEFAULT timezone('utc'::text, now()),

    CONSTRAINT support_tickets_pkey PRIMARY KEY (id)
);





-- Enable Row Level Security


ALTER TABLE public.profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scans ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.api_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.support_tickets ENABLE ROW LEVEL SECURITY;
