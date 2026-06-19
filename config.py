# SOLUM - Self-Hosted AI Memory Server
# Copyright (c) 2026 A Generation Forwordz Foundation
# Licensed under PolyForm Noncommercial 1.0.0 - see LICENSE file
#
# Central config. Override paths and keys via environment variables.

import os

# --- Server ---
HOST = os.environ.get("SOLUM_HOST", "0.0.0.0")  # Listen on all interfaces for LAN access
PORT = int(os.environ.get("SOLUM_PORT", "4320"))
SERVER_NAME = "solum"

# --- Authentication ---
# API key protects all REST endpoints (/api/capture, /api/search).
# MCP transport (/mcp) has its own auth flow and is NOT gated by this key.
# Set via environment variable for security. The default is intentionally
# obvious so nobody ships with an open server by accident.
API_KEY = os.environ.get("SOLUM_API_KEY", "change-me-before-deploy")

# Set to False to disable auth entirely (NOT recommended for shared networks)
AUTH_ENABLED = os.environ.get("SOLUM_AUTH_ENABLED", "true").lower() == "true"

# Demo mode: skip the dashboard login entirely. For the public demo instance ONLY,
# never for a real install (a real install protects your memory with the login).
DEMO_MODE = os.environ.get("SOLUM_DEMO_MODE", "").lower() == "true"

# --- Database Backend ---
# Solum runs on PostgreSQL with the pgvector extension: concurrent multi-agent
# access, in-database similarity search, scales to 1M+ thoughts. Postgres is
# required. See the README "Getting started" section for the one-time setup.
DB_BACKEND = os.environ.get("SOLUM_DB_BACKEND", "postgresql")

# --- Admin Key (for destructive operations) ---
# Destructive actions (delete thought, detach file) require this key.
# AI clients DON'T know this key, so they literally cannot delete anything
# without the human owner providing it. This is the safety net.
# If not set, delete operations are DISABLED entirely - no fallback to API_KEY.
# This prevents any API client from automatically having admin privileges.
ADMIN_KEY = os.environ.get("SOLUM_ADMIN_KEY", "")

# --- Paths ---
# Override DATA_DIR via environment variable to store the DB wherever you want.
# Default: ./data (relative to where you run the server)
DATA_DIR = os.environ.get("SOLUM_DATA_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"))
DB_PATH = os.path.join(DATA_DIR, "brain.db")
BACKUP_DIR = os.path.join(DATA_DIR, "backups")
LOG_DIR = os.environ.get("SOLUM_LOG_DIR", os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs"))

# --- Embedding Model ---
# BAAI/bge-base-en-v1.5: 768 dims, ONNX format via fastembed
# Scores better than all-mpnet-base-v2 on most benchmarks AND runs on
# Raspberry Pi without PyTorch (which needs ~1.5GB RAM on ARM).
# fastembed uses ONNX Runtime instead (~100MB RAM). Embeds in ~0.16s per thought on Pi 4B.
MODEL_NAME = "BAAI/bge-base-en-v1.5"
EMBEDDING_DIM = 768
IDLE_TIMEOUT = 300  # 5 minutes - unload model after this many seconds of no use

# --- Search Defaults ---
DEFAULT_SEARCH_LIMIT = 10
DEFAULT_RECENT_LIMIT = 20
DEFAULT_RECENT_HOURS = 168  # 7 days

# --- Deduplication ---
# When capturing a new thought, check existing thoughts for cosine similarity.
# If any existing thought scores above this threshold, warn instead of blindly saving.
# 0.85 = very similar content (likely a duplicate or near-duplicate)
# 0.90 = almost identical wording
DEDUP_THRESHOLD = 0.85

# --- Parent-child clustering ("suggest a parent" band) ---
# Second consolidation layer below dedup. A new thought scoring in
# [CLUSTER_THRESHOLD_LOW, DEDUP_THRESHOLD) is RELATED but not a near-copy:
# likely a branch of an existing project "star" (e.g. a build spec under a
# product note). It still gets saved, but capture suggests linking it as a
# child instead of leaving it as yet another scattered top-level star.
# Validated against the real #1007 sandbox-rooms cluster (its branches sit at
# 0.70–0.85); 0.70 catches all five, 0.75 would have missed the 0.704 one.
CLUSTER_THRESHOLD_LOW = 0.70

# Clear-leader gate for the parent suggestion. The cluster band alone is noisy
# on a dense corpus (lots of agent/Solum notes sit at 0.70-0.76), so we only
# suggest a parent when ONE candidate clearly stands out — either it scores at
# least CLUSTER_SUGGEST_STRONG outright, or it leads the runner-up by at least
# CLUSTER_SUGGEST_GAP. A flat field of near-ties (a busy topic area, not a real
# project branch) produces NO suggestion. We only ever suggest the single top
# candidate, never a list. Validated on #1008: #1007 leads at 0.846, an 0.087
# gap over the topical noise at ~0.76 — a clear leader; noise stays suppressed.
CLUSTER_SUGGEST_STRONG = 0.80   # top candidate this high -> always worth suggesting
CLUSTER_SUGGEST_GAP = 0.04      # ...or top leads #2 by at least this much

# --- Input Limits ---
# Prevents abuse / DoS via oversized payloads. 50KB is plenty for any note.
# Large files should be stored on disk and referenced by path, not inlined.
MAX_CONTENT_LENGTH = 50_000    # 50KB per thought - generous for text notes
MAX_TAGS = 50                   # Max tags per thought
MAX_PEOPLE = 50                 # Max people per thought
MAX_TAG_LENGTH = 100            # Max chars per individual tag
MAX_PERSON_LENGTH = 100         # Max chars per person name

# --- File Vault ---
# The vault stores actual files attached to thoughts. This is what turns
# Solum from a text memory into a full knowledge system. Thoughts are
# the semantic index; the vault holds the real content - code files, documents,
# entire projects. Organized as vault/{device}/{YYYY-MM}/{thought_id}/
VAULT_DIR = os.environ.get("SOLUM_VAULT_DIR", os.path.join(DATA_DIR, "vault"))
MAX_FILE_SIZE = 1_000_000_000          # 1GB per file - enough for a whole project archive
MAX_ATTACHMENT_CONTENT = 50_000_000    # 50MB for base64 content via MCP (larger files use REST upload)
MAX_ATTACHMENTS_PER_THOUGHT = 500     # generous cap - a project could have hundreds of files

# --- Build Info ---
# Internal build identifier for version tracking and support diagnostics.
BUILD_SIGNATURE = "AGFW-CM-MV2026"  # Do not modify - used by health endpoint

# --- Thought Types ---
# 10 types with clear descriptions so AI agents know WHEN to use each one.
# "thought" is the catch-all default. The constellation visualizes these as star colors.
VALID_TYPES = [
    "thought",      # General note that doesn't fit other categories - the catch-all
    "decision",     # A choice that was made, with reasoning - captures the WHY behind it
    "session",      # End-of-session summary - what happened, what was accomplished
    "person",       # Notes about a specific person - relationships, context, preferences
    "insight",      # A realization or learning - something clicked, a pattern recognized
    "project",      # Project-specific context - status, architecture, dependencies, goals
    "instruction",  # How-to, working preferences, rules to follow - operational guidance
    "reference",    # Technical docs, links, specs, factual records - look-up material
    "idea",         # Something that HASN'T been decided yet - brainstorm, what-if, exploration (NOT a decision)
    "observation",  # A pattern noticed but no conclusions drawn - "I noticed X keeps happening" (NOT an insight)
]
