use anyhow::Result;
use reqwest::Client;
use serde_json::{json, Value};
use tokio::sync::mpsc;
use futures_util::StreamExt;

use crate::core::config::Config;
use crate::core::models::{ChatRequest, ResponseEvent, ResponseChoice, ResponseDelta};

pub async fn stream_chat_completions(
    config: &Config, 
    request: ChatRequest
) -> Result<mpsc::Receiver<Result<ResponseEvent>>> {
    let client = Client::new();
    let (tx, rx) = mpsc::channel(100);
    let config = config.clone();

    tokio::spawn(async move {
// SOLUTION: Convert system messages to user messages with special formatting
        // ChatGPT Responses API has strict validation on instructions field
        // So we put system messages in the input array as user messages
        
        let mut input_messages = Vec::new();
        
        for msg in &request.messages {
            match msg.role.as_str() {
                "system" => {
                    input_messages.push(json!({
                        "role": "user",
                        "content": format!("<system>\n{}\n</system>", msg.content)
                    }));
                }
                "tool" => {
                    input_messages.push(json!({
                        "role": "assistant",
                        "content": format!("<tool_response>\n{}\n</tool_response>", msg.content)
                    }));
                }
                "assistant" | "user" | "developer" => {
                    input_messages.push(json!({
                        "role": msg.role,
                        "content": msg.content
                    }));
                }
                _ => {
                    input_messages.push(json!({
                        "role": "user",
                        "content": format!("<{}>\n{}\n</{}>", msg.role, msg.content, msg.role)
                    }));
                }
            }
        }
        
        // Use the full base instructions from prompt.md
        use crate::core::client_common::BASE_INSTRUCTIONS;
        
        let mut instructions = BASE_INSTRUCTIONS.to_string();
        
        // Add user instructions from AGENTS.md if available
        if let Some(user_instructions) = &config.user_instructions {
            instructions.push_str("\n\n<user_instructions>\n\n");
            instructions.push_str(user_instructions);
            instructions.push_str("\n\n</user_instructions>");
        }
        
        println!("🔍 DEBUG - Processing {} messages", request.messages.len());
        println!("🔍 DEBUG - Instructions length: {} characters", instructions.len());
        println!("🔍 DEBUG - Instructions preview: {}...", &instructions[..200.min(instructions.len())]);
        println!("🔍 DEBUG - Input messages: {}", input_messages.len());
        
        // Extract tools from the original request and map to ChatGPT Responses schema
        // Chat Completions format nests name under `function.name`; Responses expects top-level `name`
        let mapped_tools: Vec<Value> = request
            .tools
            .iter()
            .filter_map(|tool| {
                let name = tool.function.name.trim();
                if name.is_empty() || name == "null" {
                    return None;
                }
                Some(json!({
                    "type": "function",
                    "name": name,
                    // parameters is already a JSON schema in our types
                    "parameters": tool.function.parameters.clone(),
                    "strict": true  // Add strict mode for better tool calling
                }))
            })
            .collect();

        let has_tools = !mapped_tools.is_empty();

        println!("🔍 DEBUG - Tools in request: {}", request.tools.len());
        println!("🔍 DEBUG - Mapped tools included: {}", mapped_tools.len());
        println!("🔍 DEBUG - Has valid tools: {}", has_tools);
        
        // Construct payload matching ChatGPT Responses API format
        let mut payload = json!({
            "model": if request.model.starts_with("gpt-5") { "gpt-5".to_string() } else { request.model.clone() },
            "instructions": instructions,  // Full instructions from prompt.md
            "input": input_messages,        // User/assistant messages only
            "store": false,        // CRITICAL: Must be false for ChatGPT Plus plan
            "stream": true
        });
        
        // Only add tools-related fields if we have valid tools
        if has_tools {
            payload["tools"] = json!(mapped_tools);
            // Keep auto selection; the Responses API accepts "auto" here
            payload["tool_choice"] = json!("auto");
            payload["parallel_tool_calls"] = json!(false);
            println!("🔍 DEBUG - Added mapped tools to payload");
        } else {
            println!("🔍 DEBUG - No tools added to payload");
        }
        
        println!("🔍 DEBUG - Request payload: {}", serde_json::to_string_pretty(&payload).unwrap_or_else(|_| "Failed to serialize".to_string()));

        // Get access token and account ID
        println!("🔑 Getting access token...");
        let access_token = match get_access_token(&config).await {
            Ok(token) => {
                println!("✅ Access token retrieved: {}...", &token[..50.min(token.len())]);
                token
            },
            Err(e) => {
                println!("❌ Access token retrieval failed: {}", e);
                let _ = tx.send(Err(anyhow::anyhow!("Access token retrieval failed: {}", e))).await;
                return;
            }
        };

        println!("🆔 Getting account ID...");
        let account_id = match get_account_id(&config).await {
            Ok(id) => {
                println!("✅ Account ID retrieved: {}", id);
                id
            },
            Err(e) => {
                println!("❌ Account ID retrieval failed: {}", e);
                let _ = tx.send(Err(anyhow::anyhow!("Account ID retrieval failed: {}", e))).await;
                return;
            }
        };

        // Try the exact URL that working codex uses: base + codex + responses
        let url = "https://chatgpt.com/backend-api/codex/responses";
        println!("🌐 Making request to ChatGPT Responses API: {}", url);
        
        // CRITICAL: Use exact headers for ChatGPT Plus plan
        let session_id = uuid::Uuid::new_v4().to_string();
        println!("🔍 DEBUG - Headers:");
        println!("  Authorization: Bearer {}...", &access_token[..50.min(access_token.len())]);
        println!("  chatgpt-account-id: {}", account_id);
        println!("  session_id: {}", session_id);
        
        let response = match client
            .post(url)
            .header("Authorization", format!("Bearer {}", access_token))
            .header("chatgpt-account-id", &account_id)           // CRITICAL: Required for plan users
            .header("Content-Type", "application/json")
            .header("Accept", "text/event-stream")
            .header("OpenAI-Beta", "responses=experimental")    // CRITICAL: Responses API header
            .header("session_id", session_id)                   // CRITICAL: Session tracking
            .header("originator", "codex_cli_rs")               // CRITICAL: Plan identifier
            .json(&payload)
            .send()
            .await
        {
            Ok(resp) => {
                println!("✅ Got response with status: {}", resp.status());
                
                if resp.status().is_success() {
                    resp
                } else {
                    // CRITICAL: Capture response body for debugging 400 errors
                    let status = resp.status();
                    let response_body = resp.text().await.unwrap_or_else(|_| "Failed to read response body".to_string());
                    println!("❌ Failed with status: {}", status);
                    println!("🔍 DEBUG - Response body: {}", response_body);
                    
// Send properly formatted error response as SSE
                    // Transform specific error messages for better user experience
                    let user_friendly_message = if status.as_u16() == 429 && response_body.contains("usage_limit_reached") {
                        "You've hit your usage limit. Upgrade to Pro (https://openai.com/chatgpt/pricing), or wait for limits to reset (every 5h and every week.).".to_string()
                    } else {
                        format!("Error: {} - {}", status, response_body)
                    };
                    
                    let error_event = ResponseEvent {
                        id: format!("error-{}", uuid::Uuid::new_v4()),
                        object: "chat.completion.chunk".to_string(),
                        created: std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs() as i64,
                        model: request.model.clone(),
                        choices: vec![ResponseChoice {
                            index: 0,
                            delta: ResponseDelta {
                                role: Some("assistant".to_string()),
                                content: Some(user_friendly_message),
                                tool_calls: None,
                            },
                            finish_reason: Some("error".to_string()),
                        }],
                    };
                    let _ = tx.send(Ok(error_event)).await;
                    return;
                }
            },
            Err(e) => {
                println!("❌ Request failed: {}", e);
                let _ = tx.send(Err(anyhow::anyhow!("Request failed: {}", e))).await;
                return;
            }
        };

        // Handle streaming response with proper SSE buffering
        let mut stream = response.bytes_stream();
        let mut buffer = String::new();

        // Deduplication: Track last sent content
        let mut last_sent_content: Option<String> = None;

        while let Some(chunk) = stream.next().await {
            let chunk = match chunk {
                Ok(chunk) => chunk,
                Err(e) => {
let error_event = ResponseEvent {
    id: format!("error-{}", uuid::Uuid::new_v4()),
    object: "chat.completion.chunk".to_string(),
    created: std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64,
    model: request.model.clone(),
    choices: vec![ResponseChoice {
        index: 0,
        delta: ResponseDelta {
            role: Some("assistant".to_string()),
            content: Some(format!("Stream error: {}", e)),
            tool_calls: None,
        },
        finish_reason: Some("error".to_string()),
    }],
};
                    let _ = tx.send(Ok(error_event)).await;
                    break;
                }
            };

let chunk_str = match String::from_utf8(chunk.to_vec()) {
                Ok(s) => s,
                Err(e) => {
                    // Try to recover by using lossy UTF-8 conversion
                    let lossy_str = String::from_utf8_lossy(&chunk);
                    println!("⚠️  UTF-8 error: {}, using lossy conversion", e);
                    lossy_str.to_string()
                }
            };

            // Add chunk to buffer
            buffer.push_str(&chunk_str);

            // Process complete lines from buffer
            while let Some(line_end) = buffer.find('\n') {
                let line = buffer[..line_end].trim_end_matches('\r').to_string();
                buffer = buffer[line_end + 1..].to_string();

                // Skip empty lines (SSE format requirement)
                if line.is_empty() {
                    continue;
                }

                // Process SSE data lines
                if line.starts_with("data: ") {
                    let json_str = line[6..].trim(); // Remove "data: " prefix
                    
                    // Skip "[DONE]" marker
                    if json_str == "[DONE]" {
                        println!("🏁 Received [DONE] marker, ending stream");
                        return;
                    }

                    // Skip empty data lines
                    if json_str.is_empty() {
                        continue;
                    }

                    println!("🔍 DEBUG - Parsing JSON: {}", json_str);

                    match serde_json::from_str::<Value>(json_str) {
                        Ok(event_json) => {
                            // Convert to our ResponseEvent format
                            if let Some(response_event) = parse_sse_event(&event_json) {
                                // Deduplication logic
                                let mut should_send = true;
                                // Try to extract content from the event
                                let content = response_event.choices.get(0)
                                    .and_then(|choice| choice.delta.content.as_ref())
                                    .map(|s| s.trim().to_string());
                                // Only deduplicate non-empty content messages
                                if let Some(ref new_content) = content {
                                    if let Some(ref last_content) = last_sent_content {
                                        if !new_content.is_empty() && new_content == last_content {
                                            should_send = false;
                                        }
                                    }
                                }
                                if should_send {
                                    // Update last sent content if this is a non-empty message
                                    if let Some(ref new_content) = content {
                                        if !new_content.is_empty() {
                                            last_sent_content = Some(new_content.clone());
                                        }
                                    }
                                    if tx.send(Ok(response_event)).await.is_err() {
                                        // Channel closed, stop processing
                                        return;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            println!("⚠️  JSON parse error for line '{}': {}", json_str, e);
                            // Send a structured error response for malformed JSON
let error_event = ResponseEvent {
    id: format!("error-{}", uuid::Uuid::new_v4()),
    object: "chat.completion.chunk".to_string(),
    created: std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64,
    model: request.model.clone(),
    choices: vec![ResponseChoice {
        index: 0,
        delta: ResponseDelta {
            role: Some("assistant".to_string()),
            content: Some(format!("JSON parse error: {}", e)),
            tool_calls: None,
        },
        finish_reason: Some("error".to_string()),
    }],
};
                            let _ = tx.send(Ok(error_event)).await;
                            continue;
                        }
                    }
                } else if line.starts_with("event: ") {
                    // Handle SSE event types if needed
                    let event_type = &line[7..];
                    println!("📡 SSE Event type: {}", event_type);
                } else if line.starts_with("id: ") {
                    // Handle SSE event IDs if needed
                    let event_id = &line[4..];
                    println!("🆔 SSE Event ID: {}", event_id);
                }
            }
        }
    });

    Ok(rx)
}

fn parse_sse_event(event: &Value) -> Option<ResponseEvent> {
    println!("🔍 DEBUG - Raw event structure: {}", serde_json::to_string_pretty(event).unwrap_or_else(|_| "Failed to serialize".to_string()));

    // ChatGPT's Responses API has a different structure than OpenAI's
    // It might have fields like: response, message, content, etc.
    
    // Handle tool calls specifically
    if let Some(response) = event.get("response") {
        if let Some(output) = response.get("output").and_then(|o| o.as_array()) {
            // Look for function_call items in the output
            for (_index, item) in output.iter().enumerate() {
                if let Some(item_obj) = item.as_object() {
                    if let Some(item_type) = item_obj.get("type").and_then(|t| t.as_str()) {
                        // Handle function_call type items
                        if item_type == "function_call" {
                            // Extract tool call information
                            let name = item_obj.get("name").and_then(|n| n.as_str()).unwrap_or("").to_string();
                            let arguments = item_obj.get("arguments").and_then(|a| a.as_str()).unwrap_or("").to_string();
                            let call_id = item_obj.get("call_id").and_then(|id| id.as_str()).unwrap_or(&format!("call_{}", uuid::Uuid::new_v4())).to_string();
                            
                            // Create a tool call response
                            return Some(ResponseEvent {
                                id: event.get("id")
                                    .and_then(|v| v.as_str())
                                    .map(|s| s.to_string())
                                    .unwrap_or_else(|| format!("chatcmpl-{}", &uuid::Uuid::new_v4().to_string()[..8])),
                                object: "chat.completion.chunk".to_string(),
                                created: event.get("created")
                                    .and_then(|v| v.as_i64())
                                    .unwrap_or_else(|| std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs() as i64),
                                model: event.get("model")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("gpt-4")
                                    .to_string(),
                                choices: vec![ResponseChoice {
                                    index: 0,
                                    delta: ResponseDelta {
                                        role: Some("assistant".to_string()),
                                        content: None,
tool_calls: Some(serde_json::json!([{
    "id": call_id,
    "type": "function",
    "index": 0,
    "function": {
        "name": name,
        "arguments": arguments
    }
}])),
                                    },
                                    finish_reason: None,
                                }],
                            });
                        }
                    }
                }
            }
        }
    }
    
    // Try to extract content from various possible structures
    let content = extract_content_from_chatgpt_response(event);
    let model = event.get("model")
        .and_then(|v| v.as_str())
        .unwrap_or("gpt-4")
        .to_string();

    // Create OpenAI-compatible response
    Some(ResponseEvent {
        id: event.get("id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("chatcmpl-{}", &uuid::Uuid::new_v4().to_string()[..8])),
        object: "chat.completion.chunk".to_string(),
        created: event.get("created")
            .and_then(|v| v.as_i64())
            .unwrap_or_else(|| std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64),
        model,
        choices: if let Some(content) = content {
vec![ResponseChoice {
    index: 0,
    delta: ResponseDelta {
        role: Some("assistant".to_string()),
        content: Some(content),
        tool_calls: None,
    },
    finish_reason: event.get("finish_reason")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string()),
}]
        } else {
            // Check if this is a finish event
            if event.get("finish_reason").is_some() {
vec![ResponseChoice {
    index: 0,
    delta: ResponseDelta {
        role: None,
        content: None,
        tool_calls: None,
    },
    finish_reason: event.get("finish_reason")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string()),
}]
            } else {
                vec![]
            }
        },
    })
}

fn extract_content_from_chatgpt_response(event: &Value) -> Option<String> {
    // Try multiple possible paths for content in ChatGPT's response format
    
    // Handle tool calls specifically
    if let Some(response) = event.get("response") {
        if let Some(output) = response.get("output").and_then(|o| o.as_array()) {
            // Look for function_call items in the output
            for item in output {
                if let Some(item_obj) = item.as_object() {
                    if let Some(item_type) = item_obj.get("type").and_then(|t| t.as_str()) {
                        // Handle function_call type items
                        if item_type == "function_call" {
                            // This is a tool call, we want to pass it through properly
                            // Return None here so the SSE parser can handle the tool call structure directly
                            return None;
                        }
                        // Handle message type items that might contain tool results
                        else if item_type == "message" {
                            if let Some(content) = item_obj.get("content").and_then(|c| {
                                c.as_array().and_then(|arr| {
                                    arr.first().and_then(|first| {
                                        first.get("text").and_then(|t| t.as_str())
                                    })
                                })
                            }) {
                                return Some(content.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    
    // Standard OpenAI format
    if let Some(choices) = event.get("choices").and_then(|c| c.as_array()) {
        if let Some(choice) = choices.first() {
            if let Some(delta) = choice.get("delta") {
                if let Some(content) = delta.get("content").and_then(|c| c.as_str()) {
                    return Some(content.to_string());
                }
            }
            if let Some(message) = choice.get("message") {
                if let Some(content) = message.get("content").and_then(|c| c.as_str()) {
                    return Some(content.to_string());
                }
            }
        }
    }
    
    // ChatGPT Responses API format - direct content field
    if let Some(content) = event.get("content").and_then(|c| c.as_str()) {
        return Some(content.to_string());
    }
    
    // ChatGPT Responses API format - message field
    if let Some(message) = event.get("message") {
        if let Some(content) = message.get("content").and_then(|c| c.as_str()) {
            return Some(content.to_string());
        }
        if let Some(content) = message.as_str() {
            return Some(content.to_string());
        }
    }
    
    // ChatGPT Responses API format - response field
    if let Some(response) = event.get("response") {
        if let Some(content) = response.get("content").and_then(|c| c.as_str()) {
            return Some(content.to_string());
        }
        if let Some(content) = response.as_str() {
            return Some(content.to_string());
        }
    }
    
    // ChatGPT Responses API format - text field
    if let Some(text) = event.get("text").and_then(|t| t.as_str()) {
        return Some(text.to_string());
    }
    
    // ChatGPT Responses API format - delta field
    if let Some(delta) = event.get("delta") {
        if let Some(content) = delta.get("content").and_then(|c| c.as_str()) {
            return Some(content.to_string());
        }
        if let Some(text) = delta.get("text").and_then(|t| t.as_str()) {
            return Some(text.to_string());
        }
    }
    
    None
}

async fn get_access_token(config: &Config) -> Result<String> {
    use crate::login::lib::CodexAuth;

    let auth = CodexAuth::from_codex_home(&config.codex_home)?
        .ok_or_else(|| anyhow::anyhow!("No authentication found"))?;
    
    let token_data = auth.get_token_data().await?;
    Ok(token_data.access_token)
}

async fn get_account_id(config: &Config) -> Result<String> {
    use crate::login::lib::CodexAuth;

    let auth = CodexAuth::from_codex_home(&config.codex_home)?
        .ok_or_else(|| anyhow::anyhow!("No authentication found"))?;
    
    let token_data = auth.get_token_data().await?;
    token_data.account_id.ok_or_else(|| anyhow::anyhow!("No account ID found"))
}