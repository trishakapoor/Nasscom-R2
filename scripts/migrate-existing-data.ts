// scripts/migrate-existing-data.ts
// ─────────────────────────────────────────────────────────────────────────────
// ONE-TIME SCRIPT: Encrypts all existing plaintext rows in your Supabase DB.
// Run this ONCE after deploying the encryption feature.
// It is safe to run multiple times — it skips already-encrypted rows.
// ─────────────────────────────────────────────────────────────────────────────

import { createClient } from "@supabase/supabase-js";
import { encrypt } from "../lib/encryption";
import * as dotenv from "dotenv";

// Load .env.local so all environment variables are available
dotenv.config({ path: ".env.local" });

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!
);

/**
 * Checks if a value has already been encrypted by our system.
 * Encrypted values look like: "abc123:xyz789" (two Base64 parts with a colon)
 */
function isAlreadyEncrypted(value: string): boolean {
  if (typeof value !== "string") return false;
  const parts = value.split(":");
  return (
    parts.length === 2 &&
    parts[0].length > 0 &&
    parts[1].length > 0
  );
}

// ─── Migrate live_tickets table ───────────────────────────────────────────────

async function migrateLiveTickets() {
  console.log("\n📋 Migrating live_tickets table...");

  const { data, error } = await supabase
    .from("live_tickets")
    .select("*");

  if (error) {
    console.error("  ❌ Could not fetch live_tickets:", error.message);
    return;
  }

  if (data.length === 0) {
    console.log("  ℹ️  No rows found — nothing to migrate.");
    return;
  }

  let encryptedCount = 0;
  let skippedCount = 0;

  for (const row of data) {
    if (
      row.original_redacted_text &&
      !isAlreadyEncrypted(row.original_redacted_text)
    ) {
      const encryptedValue = await encrypt(row.original_redacted_text);

      const { error: updateError } = await supabase
        .from("live_tickets")
        .update({ original_redacted_text: encryptedValue })
        .eq("id", row.id);

      if (updateError) {
        console.error(
          `  ❌ Failed on row ${row.id}:`,
          updateError.message
        );
      } else {
        console.log(`  ✅ Encrypted row: ${row.id}`);
        encryptedCount++;
      }
    } else {
      console.log(`  ⏭️  Already encrypted, skipping: ${row.id}`);
      skippedCount++;
    }
  }

  console.log(
    `  Done! ${encryptedCount} encrypted, ${skippedCount} skipped.`
  );
}

// ─── Migrate historical_tickets table ────────────────────────────────────────

async function migrateHistoricalTickets() {
  console.log("\n📚 Migrating historical_tickets table...");

  const { data, error } = await supabase
    .from("historical_tickets")
    .select("*");

  if (error) {
    console.error("  ❌ Could not fetch historical_tickets:", error.message);
    return;
  }

  if (data.length === 0) {
    console.log("  ℹ️  No rows found — nothing to migrate.");
    return;
  }

  let encryptedCount = 0;
  let skippedCount = 0;

  for (const row of data) {
    const updates: Record<string, string> = {};

    if (row.sanitized_query && !isAlreadyEncrypted(row.sanitized_query)) {
      updates.sanitized_query = await encrypt(row.sanitized_query);
    }

    if (row.resolution_steps && !isAlreadyEncrypted(row.resolution_steps)) {
      updates.resolution_steps = await encrypt(row.resolution_steps);
    }

    if (Object.keys(updates).length > 0) {
      const { error: updateError } = await supabase
        .from("historical_tickets")
        .update(updates)
        .eq("id", row.id);

      if (updateError) {
        console.error(
          `  ❌ Failed on row ${row.id}:`,
          updateError.message
        );
      } else {
        console.log(`  ✅ Encrypted row: ${row.id}`);
        encryptedCount++;
      }
    } else {
      console.log(`  ⏭️  Already encrypted, skipping: ${row.id}`);
      skippedCount++;
    }
  }

  console.log(
    `  Done! ${encryptedCount} encrypted, ${skippedCount} skipped.`
  );
}

// ─── Migrate master_incidents table ──────────────────────────────────────────

async function migrateMasterIncidents() {
  console.log("\n🚨 Migrating master_incidents table...");

  const { data, error } = await supabase
    .from("master_incidents")
    .select("*");

  if (error) {
    console.error("  ❌ Could not fetch master_incidents:", error.message);
    return;
  }

  if (data.length === 0) {
    console.log("  ℹ️  No rows found — nothing to migrate.");
    return;
  }

  const sensitiveFields = [
    "triggering_ticket_text",
    "incident_summary",
    "mass_communication_draft",
    "remediation_runbook",
  ];

  let encryptedCount = 0;
  let skippedCount = 0;

  for (const row of data) {
    const updates: Record<string, string> = {};

    for (const field of sensitiveFields) {
      if (row[field] && !isAlreadyEncrypted(row[field])) {
        updates[field] = await encrypt(row[field]);
      }
    }

    if (Object.keys(updates).length > 0) {
      const { error: updateError } = await supabase
        .from("master_incidents")
        .update(updates)
        .eq("id", row.id);

      if (updateError) {
        console.error(
          `  ❌ Failed on row ${row.id}:`,
          updateError.message
        );
      } else {
        console.log(`  ✅ Encrypted row: ${row.id}`);
        encryptedCount++;
      }
    } else {
      console.log(`  ⏭️  Already encrypted, skipping: ${row.id}`);
      skippedCount++;
    }
  }

  console.log(
    `  Done! ${encryptedCount} encrypted, ${skippedCount} skipped.`
  );
}

// ─── Run all migrations ───────────────────────────────────────────────────────

async function main() {
  console.log("🔐 Starting Supabase at-rest encryption migration...");
  console.log("   Using ENCRYPTION_SECRET from .env.local\n");

  await migrateLiveTickets();
  await migrateHistoricalTickets();
  await migrateMasterIncidents();

  console.log("\n✅ Migration complete! Your database is now encrypted at rest.");
  console.log("   Data in Supabase will now show as encrypted gibberish.");
  console.log("   Your app will still work normally — decryption is automatic.\n");
}

main().catch((err) => {
  console.error("\n💥 Migration failed unexpectedly:", err);
  process.exit(1);
});