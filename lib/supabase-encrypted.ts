// lib/supabase-encrypted.ts
// ─────────────────────────────────────────────────────────────────────────────
// USE THESE FUNCTIONS instead of calling supabase directly for ticket ops.
// They automatically encrypt data before saving and decrypt when reading.
// Your UI and API logic don't need to change — encryption is invisible.
// ─────────────────────────────────────────────────────────────────────────────

import { createClient } from "@supabase/supabase-js";
import { encryptFields, decryptFields } from "./encryption";

// Server-side Supabase client using the SERVICE ROLE key
// This key has full database access — never expose it to the browser
const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
);

// ─── Which fields to encrypt in each table ────────────────────────────────────
// Only text fields that contain sensitive user data are encrypted.
// The 'embedding' vector field is intentionally LEFT UNENCRYPTED
// because it's needed for pgvector cosine similarity search (RAG).
// 'category', 'status', 'confidence_score' are also left unencrypted
// because they're needed for filtering and routing logic.

const LIVE_TICKET_SENSITIVE_FIELDS = [
  "original_redacted_text",
];

const HISTORICAL_TICKET_SENSITIVE_FIELDS = [
  "sanitized_query",
  "resolution_steps",
];

const MASTER_INCIDENT_SENSITIVE_FIELDS = [
  "triggering_ticket_text",
  "incident_summary",
  "mass_communication_draft",
  "remediation_runbook",
];

// ─── LIVE TICKETS ─────────────────────────────────────────────────────────────

/**
 * Inserts a new live ticket into Supabase with sensitive fields encrypted.
 * 
 * USE THIS instead of:
 *   supabase.from("live_tickets").insert({ ... })
 */
export async function insertLiveTicket(ticket: Record<string, unknown>) {
  console.log("[encryption] Encrypting live_ticket before saving to Supabase...");

  // Encrypt the sensitive fields before they touch the database
  const encryptedTicket = await encryptFields(
    ticket,
    LIVE_TICKET_SENSITIVE_FIELDS
  );

  const { data, error } = await supabase
    .from("live_tickets")
    .insert(encryptedTicket)
    .select()
    .single();

  if (error) throw error;

  // Decrypt the returned data so the rest of your app can use it normally
  return decryptFields(data, LIVE_TICKET_SENSITIVE_FIELDS);
}

/**
 * Fetches a single live ticket by ID with sensitive fields decrypted.
 * 
 * USE THIS instead of:
 *   supabase.from("live_tickets").select("*").eq("id", id)
 */
export async function getLiveTicket(id: string) {
  const { data, error } = await supabase
    .from("live_tickets")
    .select("*")
    .eq("id", id)
    .single();

  if (error) throw error;

  return decryptFields(data, LIVE_TICKET_SENSITIVE_FIELDS);
}

/**
 * Fetches ALL live tickets with sensitive fields decrypted.
 * Used for admin dashboards or ticket list views.
 */
export async function getAllLiveTickets() {
  const { data, error } = await supabase
    .from("live_tickets")
    .select("*")
    .order("created_at", { ascending: false });

  if (error) throw error;

  // Decrypt every row
  return Promise.all(
    data.map((row) => decryptFields(row, LIVE_TICKET_SENSITIVE_FIELDS))
  );
}

// ─── HISTORICAL TICKETS ───────────────────────────────────────────────────────

/**
 * Inserts a historical ticket with sensitive fields encrypted.
 * 
 * IMPORTANT: The 'embedding' vector is NOT encrypted on purpose.
 * pgvector needs the raw float array to do similarity search.
 */
export async function insertHistoricalTicket(
  ticket: Record<string, unknown>
) {
  console.log("[encryption] Encrypting historical_ticket before saving...");

  const encryptedTicket = await encryptFields(
    ticket,
    HISTORICAL_TICKET_SENSITIVE_FIELDS
  );

  const { data, error } = await supabase
    .from("historical_tickets")
    .insert(encryptedTicket)
    .select()
    .single();

  if (error) throw error;

  return decryptFields(data, HISTORICAL_TICKET_SENSITIVE_FIELDS);
}

/**
 * Fetches a single historical ticket by ID, decrypted.
 */
export async function getHistoricalTicket(id: string) {
  const { data, error } = await supabase
    .from("historical_tickets")
    .select("*")
    .eq("id", id)
    .single();

  if (error) throw error;

  return decryptFields(data, HISTORICAL_TICKET_SENSITIVE_FIELDS);
}

// ─── MASTER INCIDENTS ─────────────────────────────────────────────────────────

/**
 * Inserts a master incident report with all sensitive fields encrypted.
 * This is triggered when 3+ similar tickets arrive within 72 hours.
 */
export async function insertMasterIncident(
  incident: Record<string, unknown>
) {
  console.log("[encryption] Encrypting master_incident before saving...");

  const encryptedIncident = await encryptFields(
    incident,
    MASTER_INCIDENT_SENSITIVE_FIELDS
  );

  const { data, error } = await supabase
    .from("master_incidents")
    .insert(encryptedIncident)
    .select()
    .single();

  if (error) throw error;

  return decryptFields(data, MASTER_INCIDENT_SENSITIVE_FIELDS);
}

/**
 * Fetches a single master incident by ID, decrypted.
 */
export async function getMasterIncident(id: string) {
  const { data, error } = await supabase
    .from("master_incidents")
    .select("*")
    .eq("id", id)
    .single();

  if (error) throw error;

  return decryptFields(data, MASTER_INCIDENT_SENSITIVE_FIELDS);
}

/**
 * Fetches ALL master incidents, decrypted.
 */
export async function getAllMasterIncidents() {
  const { data, error } = await supabase
    .from("master_incidents")
    .select("*")
    .order("created_at", { ascending: false });

  if (error) throw error;

  return Promise.all(
    data.map((row) => decryptFields(row, MASTER_INCIDENT_SENSITIVE_FIELDS))
  );
}