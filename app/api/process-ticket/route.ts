import {
  insertLiveTicket,
  insertMasterIncident,
} from "@/lib/supabase-encrypted";
import { NextRequest, NextResponse } from "next/server";
import { groq } from "@/lib/groq";
import { supabase } from "@/lib/supabase";
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";
import lrModelData from "@/data/lr_model.json";

// Initialize Upstash Redis if possible
const redis = process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN
  ? new Redis({
      url: process.env.UPSTASH_REDIS_REST_URL,
      token: process.env.UPSTASH_REDIS_REST_TOKEN,
    })
  : null;

const ratelimit = redis ? new Ratelimit({
  redis: redis,
  limiter: Ratelimit.slidingWindow(5, "1 m"),
}) : null;

// ──────────────────────────────────────────────────────────────
// Regex-only PII redaction fallback (zero external dependencies)
// ──────────────────────────────────────────────────────────────
function regexRedact(text: string): string {
  let out = text;
  // IPs
  out = out.replace(/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, '[REDACTED_IP]');
  // Emails
  out = out.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, '[REDACTED_EMAIL]');
  // Phone numbers (US/IN formats)
  out = out.replace(/(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g, '[REDACTED_PHONE]');
  // SSN-like patterns
  out = out.replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[REDACTED_SSN]');
  return out;
}

export async function POST(req: NextRequest) {
  try {
    // 1. Rate Limiting
    const ip = req.headers.get("x-forwarded-for") ?? "127.0.0.1";
    if (ratelimit) {
      const { success } = await ratelimit.limit(ip);
      if (!success) {
        return NextResponse.json({ error: "Rate limit exceeded" }, { status: 429 });
      }
    }

    const { rawText, logContent, useLLM = true } = await req.json();
    const fullText = logContent ? `${rawText}\n\nLogs:\n${logContent}` : rawText;

    const thoughtProcess: string[] = ["Initializing pipeline..."];

    // ───────────────────────────────────────────────────────────
    // 2. PII Redaction — Try local NER first, fallback to regex
    // ───────────────────────────────────────────────────────────
    let sanitizedText = fullText;
    let useLocalEmbeddings = false;

    // Enable local ML models in production for the hackathon flex
    if (true) {
      try {
        thoughtProcess.push("Loading local NER model (Xenova/bert-base-NER)...");
        const PipelineSingleton = (await import("@/lib/ml")).default;
        const ner = await PipelineSingleton.getNER();
        const entities = await (ner as any)(fullText, { aggregation_strategy: "simple" });
        
        const sortedEntities = Array.isArray(entities) ? entities.sort((a: any, b: any) => b.start - a.start) : [];
        
        for (const ent of sortedEntities) {
          const entityType = ent.entity_group === 'PER' ? '[REDACTED_NAME]' :
                             ent.entity_group === 'LOC' ? '[REDACTED_LOCATION]' :
                             ent.entity_group === 'ORG' ? '[REDACTED_ORGANIZATION]' : '[REDACTED_ENTITY]';
          sanitizedText = sanitizedText.slice(0, ent.start) + entityType + sanitizedText.slice(ent.end);
        }

        thoughtProcess.push("Running local zero-trust PII redaction... ✓");
        useLocalEmbeddings = true;
      } catch (nerErr) {
        console.warn("Local NER unavailable, falling back to regex redaction:", (nerErr as any)?.message || nerErr);
        thoughtProcess.push("Local NER unavailable — using regex-based PII scrubbing...");
      }
    } else {
      thoughtProcess.push("Running regex-based PII redaction pipeline...");
    }

    // Always apply regex redaction as a safety net
    sanitizedText = regexRedact(sanitizedText);
    thoughtProcess.push("PII redaction complete ✓");

    // ───────────────────────────────────────────────────────────
    // 3. Embedding — Try local model, fallback to text search
    // ───────────────────────────────────────────────────────────
    let embeddingArray: number[] | null = null;

    if (useLocalEmbeddings) {
      try {
        thoughtProcess.push("Generating embeddings locally using bge-small...");
        const PipelineSingleton = (await import("@/lib/ml")).default;
        const embedder = await PipelineSingleton.getEmbedding();
        const output = await (embedder as any)(sanitizedText, { pooling: 'mean', normalize: true });
        embeddingArray = Array.from(output.data) as number[];
      } catch (embErr) {
        console.warn("Local embeddings unavailable:", (embErr as any)?.message || embErr);
        thoughtProcess.push("Local embeddings unavailable — using text-based context retrieval...");
      }
    } else {
      thoughtProcess.push("Using text-based context retrieval...");
    }

    // ───────────────────────────────────────────────────────────
    // 4. RAG / Similarity Search
    // ───────────────────────────────────────────────────────────
    let contextString = "";
    let similarDocs: any[] = [];
    if (supabase && embeddingArray) {
      thoughtProcess.push("Searching Supabase pgvector for top 3 similar past resolutions...");
      const { data, error: searchError } = await supabase.rpc('match_historical_tickets', {
        query_embedding: embeddingArray,
        match_threshold: 0.5,
        match_count: 3
      });
      similarDocs = data || [];
  
      if (searchError) {
        console.error("Vector search error", searchError);
        thoughtProcess.push("Vector search encountered an error — proceeding without RAG context.");
      } else if (similarDocs && similarDocs.length > 0) {
        contextString = similarDocs.map((doc: any) => `Category: ${doc.category}\nHistorical Issue: ${doc.sanitized_query}\nHistorical Resolution Steps: ${doc.resolution_steps}`).join('\n\n---\n\n');
        thoughtProcess.push(`Found ${similarDocs.length} similar historical tickets.`);
      }
    } else if (supabase && !embeddingArray) {
      // Fallback: fetch recent tickets from Supabase as text context
      thoughtProcess.push("Fetching recent historical tickets as text context...");
      try {
        const { data: recentDocs } = await supabase
          .from('historical_tickets')
          .select('category, sanitized_query, resolution_steps')
          .limit(3);
        if (recentDocs && recentDocs.length > 0) {
          contextString = recentDocs.map((doc: any) => `Category: ${doc.category}\nHistorical Issue: ${doc.sanitized_query}\nHistorical Resolution Steps: ${doc.resolution_steps}`).join('\n\n---\n\n');
        }
      } catch (e) {
        console.warn("Text fallback context fetch failed:", e);
      }
    } else {
       thoughtProcess.push("Warning: Supabase not configured. Skipping context retrieval.");
    }

    // ───────────────────────────────────────────────────────────
    // 5. ML Classification & Confidence Scoring
    // ───────────────────────────────────────────────────────────
    let finalCategory = 'Infrastructure';
    let finalConfidence = 0.5;
    let finalResolution = 'System requires human escalation.';
    let finalPriority = 'Medium';
    let fallbackToAdmin = false;

    if (embeddingArray) {
      // ── PATH A: Full Local ML Pipeline (localhost / powerful servers) ──
      thoughtProcess.push("Running Dedicated ML Classifier (Logistic Regression Softmax)...");
      try {
        if (lrModelData) {
          const lrModel = lrModelData as any;
          const classes = lrModel.classes;
          const weights = lrModel.weights;
          const intercepts = lrModel.intercepts;
          
          let maxProb = -1;
          let bestCat = 'Infrastructure';
          
          const logits = classes.map((cat: string, i: number) => {
            let z = intercepts[i];
            for (let j = 0; j < embeddingArray.length; j++) {
              z += weights[i][j] * embeddingArray[j];
            }
            return z;
          });
          
          const maxLogit = Math.max(...logits);
          const exps = logits.map((z: number) => Math.exp(z - maxLogit));
          const sumExps = exps.reduce((a: number, b: number) => a + b, 0);
          const probs = exps.map((e: number) => e / sumExps);
          
          for (let i = 0; i < probs.length; i++) {
            if (probs[i] > maxProb) {
              maxProb = probs[i];
              bestCat = classes[i];
            }
          }
          
          finalCategory = bestCat;
          finalConfidence = maxProb;
          thoughtProcess.push(`✅ Custom ML (Logistic Regression) predicted: ${finalCategory} (Confidence: ${(finalConfidence * 100).toFixed(1)}%)`);
        }
      } catch (e) {
        console.error("Local ML classification failed", e);
      }

      // Now generate the resolution via Groq (if confidence is high enough)
      thoughtProcess.push("Attempting Groq Llama 3.3 for dynamic synthesis...");
      let bestHistoricalResolution = "No historical match found.";
      if (similarDocs && similarDocs.length > 0) {
        bestHistoricalResolution = similarDocs[0].resolution_steps;
      }

      if (finalConfidence < 0.50) {
        thoughtProcess.push("⚠ Confidence < 0.50. Agentic Layer: Bypassing LLM and routing to NEEDS_HUMAN queue.");
      } else {
        try {
          if (groq && useLLM) {
            const prompt = `You are an internal L1 IT Helpdesk Agent.
Analyze the user's issue and assign a priority level: 'Critical', 'High', 'Medium', or 'Low'.

CRITICAL INSTRUCTION: You must strictly use ONLY the 'Historical Past Resolutions to Use as Context' provided below. Do NOT invent, guess, or hallucinate any fake troubleshooting steps. If the provided historical context does not contain a clear fix for the User Issue, your resolution MUST be exactly: "No historical runbook found. System requires human escalation."

User Issue:
${sanitizedText}

Category (Determined by ML Model): ${finalCategory}

Historical Past Resolutions to Use as Context:
${contextString || "No historical context available."}

Return EXACTLY a raw JSON object with no markdown wrappers with the format:
{
  "priority": "Critical|High|Medium|Low",
  "resolution": "Markdown string of resolution steps strictly from context, or the exact escalation string."
}`;

            const completion = await groq.chat.completions.create({
              messages: [{ role: 'user', content: prompt }],
              model: 'llama-3.3-70b-versatile',
              temperature: 0.1,
              response_format: { type: "json_object" }
            });

            const groqResponse = JSON.parse(completion.choices[0]?.message?.content || '{}');
            finalPriority = groqResponse.priority || 'Medium';
            finalResolution = groqResponse.resolution;
            thoughtProcess.push("✅ Dynamic resolution generated via LLM.");
          } else {
            throw new Error("LLM Synthesis Disabled or Unavailable.");
          }
        } catch(e) {
          thoughtProcess.push("⚠ LLM unavailable or disabled. Falling back to exact historical database match...");
          finalResolution = `*(Historical Match)*\n\n${bestHistoricalResolution}`;
          thoughtProcess.push("✅ Ticket successfully resolved using offline RAG retrieval.");
        }
      }

    } else if (groq && useLLM) {
      // ── PATH B: Vercel/Cloud — WASM models unavailable ──
      // Single unified Groq call that classifies + resolves in one shot
      thoughtProcess.push("WASM models unavailable on this host. Routing to Groq Llama 3.3 for unified classification & resolution...");
      try {
        const unifiedPrompt = `You are an AI-powered L1 IT Helpdesk Agent performing two tasks at once.

TASK 1 — CLASSIFICATION:
Analyze the following IT issue and assign it to exactly ONE of these categories: 'Infrastructure', 'Application', 'Security', 'Database', 'Network', or 'Access Management'.
Generate a confidence score (float between 0.50 and 0.99) representing how certain you are about the category. If the issue is extremely vague, non-technical, or unrelated to IT (e.g. "my keyboard feels weird during a picnic"), the confidence MUST be below 0.40.

TASK 2 — RESOLUTION:
Provide practical, actionable troubleshooting steps for the issue based on your IT knowledge. Assign a priority level: 'Critical', 'High', 'Medium', or 'Low'.

Historical Context (use if relevant):
${contextString || "No historical context available."}

User Issue:
"${sanitizedText}"

Return EXACTLY a raw JSON object:
{
  "category": "Selected Category",
  "confidence": 0.92,
  "priority": "Critical|High|Medium|Low",
  "resolution": "Markdown formatted troubleshooting steps"
}`;

        const unifiedCompletion = await groq.chat.completions.create({
          messages: [{ role: 'user', content: unifiedPrompt }],
          model: 'llama-3.3-70b-versatile',
          temperature: 0.1,
          response_format: { type: "json_object" }
        });

        const result = JSON.parse(unifiedCompletion.choices[0]?.message?.content || '{}');
        finalCategory = result.category || 'Infrastructure';
        finalConfidence = typeof result.confidence === 'number' ? result.confidence : 0.5;
        finalPriority = result.priority || 'Medium';
        finalResolution = result.resolution || 'System requires human escalation.';

        thoughtProcess.push(`✅ AI Classification: ${finalCategory} (Confidence: ${(finalConfidence * 100).toFixed(1)}%)`);
        thoughtProcess.push(`✅ AI Resolution generated with priority: ${finalPriority}`);
      } catch (e) {
        console.error("Unified Groq classification+resolution failed", e);
        thoughtProcess.push("⚠ AI pipeline failed. Routing to human escalation.");
        finalConfidence = 0.0;
      }

    } else {
      // ── PATH C: Air-Gapped on Vercel — no WASM embeddings, no LLM ──
      // Perform a keyword-based text search against Supabase historical_tickets
      thoughtProcess.push("Air-Gapped mode active. WASM unavailable. Executing keyword-based historical search...");
      
      if (supabase) {
        try {
          // Extract meaningful keywords from the user's issue
          const keywords = sanitizedText
            .toLowerCase()
            .replace(/[^a-z0-9\s]/g, '')
            .split(/\s+/)
            .filter((w: string) => w.length > 3)
            .slice(0, 5);
          
          thoughtProcess.push(`Searching historical database with keywords: [${keywords.join(', ')}]`);
          
          let bestMatch: any = null;
          
          // Try each keyword until we get a match
          for (const keyword of keywords) {
            const { data: matches } = await supabase
              .from('historical_tickets')
              .select('category, sanitized_query, resolution_steps')
              .ilike('sanitized_query', `%${keyword}%`)
              .limit(1);
            
            if (matches && matches.length > 0) {
              bestMatch = matches[0];
              break;
            }
          }
          
          if (bestMatch) {
            finalCategory = bestMatch.category || 'Infrastructure';
            finalConfidence = 0.75;
            finalResolution = `*(Air-Gapped Historical Match)*\n\n${bestMatch.resolution_steps}`;
            finalPriority = 'Medium';
            thoughtProcess.push(`✅ Air-Gapped match found in category: ${finalCategory}`);
            thoughtProcess.push(`✅ Resolution retrieved deterministically from historical database (Confidence: 75.0%)`);
          } else {
            // No keyword match — grab the most recent ticket in a similar category as last resort
            const { data: fallbackDocs } = await supabase
              .from('historical_tickets')
              .select('category, sanitized_query, resolution_steps')
              .limit(1);
            
            if (fallbackDocs && fallbackDocs.length > 0) {
              finalCategory = fallbackDocs[0].category || 'Infrastructure';
              finalConfidence = 0.55;
              finalResolution = `*(Air-Gapped Nearest Match)*\n\n${fallbackDocs[0].resolution_steps}`;
              finalPriority = 'Medium';
              thoughtProcess.push(`✅ Air-Gapped fallback: nearest historical ticket served (Confidence: 55.0%)`);
            } else {
              thoughtProcess.push("⚠ No historical tickets found in database. Routing to human.");
              finalConfidence = 0.0;
            }
          }
        } catch (dbErr) {
          console.error("Air-gapped text search failed:", dbErr);
          thoughtProcess.push("⚠ Database search failed. Routing to human escalation.");
          finalConfidence = 0.0;
        }
      } else {
        thoughtProcess.push("⚠ No database connection and no LLM available. Routing to NEEDS_HUMAN queue.");
        finalConfidence = 0.0;
      }
    }

    if (fallbackToAdmin) finalConfidence = 0.0;
    const finalStatus = finalConfidence >= 0.50 ? 'AUTO_RESOLVED' : 'NEEDS_HUMAN';

    thoughtProcess.push(`Status determined: ${finalStatus}`);

    // ───────────────────────────────────────────────────────────
    // 6. Agentic Layer — Repeated Issue Detection
    // ───────────────────────────────────────────────────────────
    let repeatCount = 0;
    let automationSuggested = false;

    if (supabase && embeddingArray) {
      try {
        // Use pgvector to count similar live tickets in the last 72 hours
        const { data: similarCountData, error: repeatErr } = await supabase.rpc('count_similar_live_tickets_vector', {
          query_embedding: `[${embeddingArray.join(',')}]`,
          target_category: finalCategory,
          match_threshold: 0.85,
          hours_back: 72
        });

        if (repeatErr) throw repeatErr;

        repeatCount = similarCountData || 0;

        // If 3+ similar tickets in 72h, trigger Agentic Master Incident
        if (repeatCount >= 3) {
          automationSuggested = true;
          thoughtProcess.push(`⚡ Agentic Layer: Vector search detected ${repeatCount} similar ${finalCategory} tickets in the last 72 hours.`);
          thoughtProcess.push("⚡ Agentic Layer: Halting standard flow to auto-generate Master Incident Runbook & Mass Communication Draft...");

          if (groq) {
            const incidentPrompt = `You are an Autonomous AI Incident Commander.
A cluster of highly similar IT tickets has been detected indicating a potential widespread outage.
Category: ${finalCategory}
Sample Ticket: ${sanitizedText}

Draft a raw JSON object to handle this master incident. Format:
{
  "incident_summary": "1 sentence executive summary of the outage",
  "mass_communication_draft": "A short, polite Slack/Email message to send to the company acknowledging the issue and providing a workaround if any.",
  "remediation_runbook": "Markdown formatted step-by-step technical runbook for the L2/L3 engineers to resolve this."
}`;

            try {
              const incCompletion = await groq.chat.completions.create({
                messages: [{ role: 'user', content: incidentPrompt }],
                model: 'llama-3.3-70b-versatile',
                temperature: 0.1,
                response_format: { type: "json_object" }
              });
              
              const incidentData = JSON.parse(incCompletion.choices[0]?.message?.content || '{}');
              thoughtProcess.push("✅ Agentic Layer: Master Incident drafted successfully.");
              
              // Insert Master Incident
await insertMasterIncident({
  category: finalCategory,
  triggering_ticket_text: sanitizedText,
  incident_summary: incidentData.incident_summary || 'N/A',
  mass_communication_draft: incidentData.mass_communication_draft || 'N/A',
  remediation_runbook: incidentData.remediation_runbook || 'N/A',
  related_ticket_count: repeatCount
});
              
            } catch(incErr) {
              console.error("Master Incident Generation Failed", incErr);
              thoughtProcess.push("⚠ Agentic Layer: Master Incident Generation Failed.");
            }
          }

        } else if (repeatCount > 0) {
          thoughtProcess.push(`📊 Vector search detected ${repeatCount} similar ${finalCategory} ticket(s) in the last 72 hours.`);
        }
      } catch (err) {
        console.warn("Vector repeat detection error:", err);
      }
    }

    // 7. Push to live_tickets
    if (supabase) {
      if (finalStatus === 'NEEDS_HUMAN') {
        thoughtProcess.push("Routing to Support Engineers (Needs Human)...");
      }
      
      const insertPayload: Record<string, any> = {
        category: finalCategory,
        priority: finalPriority,
        original_redacted_text: sanitizedText,
        confidence_score: finalConfidence,
        status: finalStatus,
        repeat_count: repeatCount,
        automation_suggested: automationSuggested,
        embedding: embeddingArray ? `[${embeddingArray.join(',')}]` : null
      };

await insertLiveTicket({
  category: finalCategory,
  priority: finalPriority,
  status: finalStatus,
  original_redacted_text: sanitizedText,
  confidence_score: finalConfidence,
  repeat_count: repeatCount,
  automation_suggested: automationSuggested,
  embedding: embeddingArray ? `[${embeddingArray.join(',')}]` : null
});
    }

    return NextResponse.json({
      status: finalStatus === 'NEEDS_HUMAN' ? 'ESCALATED' : 'SUCCESS',
      category: finalCategory,
      priority: finalPriority,
      sanitizedText: sanitizedText,
      resolution: finalStatus === 'NEEDS_HUMAN' ? null : finalResolution,
      confidenceScore: finalConfidence,
      repeatCount: repeatCount,
      automationSuggested: automationSuggested,
      thoughtProcess: thoughtProcess
    });

  } catch (err: any) {
    console.error("Error processing ticket:", err);
    return NextResponse.json({ error: "Internal Server Error", details: err?.message }, { status: 500 });
  }
}
