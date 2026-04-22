#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "EdgeProxyServer.h"
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <stdexcept>
#include <algorithm>
#include <thread>
#include <chrono>

// ==========================================
// 1. UTILITÁRIOS E CONFIGURAÇÃO
// ==========================================

void Logger::Info(const std::string& msg) { std::cout << "[INFO] " << msg << std::endl; }
void Logger::Error(const std::string& msg) { std::cerr << "[ERRO] " << msg << std::endl; }
void Logger::Debug(const std::string& msg) { std::cout << "[DEBUG] " << msg << std::endl; }

void Config::LoadFromEnvironment()
{
  const char* envKey = std::getenv("OPENAI_API_KEY");
  if (!envKey) throw std::runtime_error("OPENAI_API_KEY (Token GitHub) nao configurada!");
  _apiKey = envKey;

  const char* envPort = std::getenv("PROXY_PORT");
  _port = envPort ? std::stoi(envPort) : 8080;

  const char* tempDir = std::getenv("TEMP");
  _vaultPath = tempDir ? std::string(tempDir) + "\\ip_vault_map.json" : "C:\\Temp\\ip_vault_map.json";

  const char* envModel = std::getenv("TARGET_MODEL");
  _targetModel = envModel ? envModel : "gpt-4o";
}

// ==========================================
// 2. DOMÍNIO: GERENCIAMENTO DE IP (VAULT)
// ==========================================

void IpVault::LoadFromFile(const std::string& filepath)
{
  std::ifstream file(filepath);
  if (!file.is_open()) { Logger::Error("Vault nao encontrado em: " + filepath); return; }

  try {
    nlohmann::json j;
    file >> j;
    for (auto& item : j.items()) {
      _realToMask[item.key()] = item.value();
      _maskToReal[item.value()] = item.key();
      _sortedRealKeys.push_back(item.key());
      _sortedMaskKeys.push_back(item.value());
    }
    auto sortByLengthDesc = [](const std::string& a, const std::string& b) { return a.length() > b.length(); };
    std::sort(_sortedRealKeys.begin(), _sortedRealKeys.end(), sortByLengthDesc);
    std::sort(_sortedMaskKeys.begin(), _sortedMaskKeys.end(), sortByLengthDesc);
    Logger::Info("Vault carregado. Entidades: " + std::to_string(_realToMask.size()));
  }
  catch (...) { Logger::Error("Erro ao ler JSON do Vault."); }
}

// ==========================================
// 3. CORE: MOTOR DE SANITIZAÇÃO
// ==========================================

void Sanitizer::InitializeRules(const IpVault& vault)
{
  _sanitizeRules.clear();
  _restoreRules.clear();
  for (const std::string& realName : vault.GetSortedRealKeys())
    _sanitizeRules.push_back({ std::regex("\\b" + realName + "\\b"), vault.GetMasked(realName) });

  for (const std::string& maskName : vault.GetSortedMaskKeys())
    _restoreRules.push_back({ std::regex("\\b" + maskName + "\\b"), vault.GetReal(maskName) });
}

std::string Sanitizer::SanitizeString(const std::string& text) const
{
  std::string result = text;
  for (const auto& rule : _sanitizeRules) result = std::regex_replace(result, rule.pattern, rule.replacement);
  return result;
}

std::string Sanitizer::RestoreString(const std::string& text) const
{
  std::string result = text;
  for (const auto& rule : _restoreRules) result = std::regex_replace(result, rule.pattern, rule.replacement);
  return result;
}

void Sanitizer::SanitizeJsonPayload(nlohmann::json& payload, const std::string& targetModel) const
{
  payload["model"] = targetModel;
  payload["stream"] = false;

  if (payload.contains("messages") && payload["messages"].is_array())
  {
    for (auto& msg : payload["messages"])
    {
      if (msg.contains("content") && msg["content"].is_string())
        msg["content"] = SanitizeString(msg["content"].get<std::string>());
    }
  }
}

void Sanitizer::RestoreJsonPayload(nlohmann::json& payload) const
{
  if (payload.contains("choices") && payload["choices"].is_array())
  {
    for (auto& choice : payload["choices"])
    {
      if (choice.contains("message") && choice["message"].contains("content") && choice["message"]["content"].is_string())
        choice["message"]["content"] = RestoreString(choice["message"]["content"].get<std::string>());
    }
  }
}

// ==========================================
// 4. INFRAESTRUTURA: CLIENTE LLM E HANDLER
// ==========================================

OpenAiClient::OpenAiClient(const std::string& key) : _apiKey(key) {}

httplib::Result OpenAiClient::PostChatCompletion(const std::string& jsonBody) const
{
  httplib::SSLClient cli("models.inference.ai.azure.com");
  cli.set_bearer_token_auth(_apiKey);
  cli.set_read_timeout(120, 0);
  return cli.Post("/chat/completions", jsonBody, "application/json");
}

CompletionHandler::CompletionHandler(const Sanitizer& s, const OpenAiClient& c, const std::string& model)
  : _sanitizer(s), _llmClient(c), _targetModel(model) {
}

void CompletionHandler::HandleRequest(const httplib::Request& req, httplib::Response& res) const
{
  try
  {
    nlohmann::json reqJson = nlohmann::json::parse(req.body);
    _sanitizer.SanitizeJsonPayload(reqJson, _targetModel);

    std::string cleanedBody = reqJson.dump();
    std::cout << "\n[OK] Requisicao convertida. Enviando para LLM..." << std::endl;

    auto apiRes = _llmClient.PostChatCompletion(cleanedBody);

    if (!apiRes || apiRes->status != 200)
    {
      Logger::Error("Erro Cloud: " + (apiRes ? std::to_string(apiRes->status) : "Timeout"));
      res.status = apiRes ? apiRes->status : 502;
      res.set_content(apiRes ? apiRes->body : R"({"error": "Cloud Timeout"})", "application/json");
      return;
    }

    nlohmann::json resJson = nlohmann::json::parse(apiRes->body);
    _sanitizer.RestoreJsonPayload(resJson);

    res.status = 200;
    res.set_content(resJson.dump(), "application/json");
    std::cout << "[OK] Resposta entregue com sucesso." << std::endl;
  }
  catch (const std::exception& e)
  {
    Logger::Error("Erro Interno: ");
    Logger::Error(e.what());
    res.status = 500;
  }
}

// ==========================================
// 5. MAIN COM SUPER DEBUGGER E GATEWAY
// ==========================================

int main()
{
  try
  {
    Config config;
    config.LoadFromEnvironment();

    IpVault vault;
    vault.LoadFromFile(config.GetVaultPath());

    Sanitizer sanitizer;
    sanitizer.InitializeRules(vault);

    OpenAiClient llmClient(config.GetApiKey());
    CompletionHandler handler(sanitizer, llmClient, config.GetTargetModel());

    httplib::Server svr;

    svr.set_logger([](const httplib::Request& req, const httplib::Response& res) {
      std::cout << "\n============================================\n";
      std::cout << "[RAW DETECT] ALGUEM BATEU NA PORTA!\n";
      std::cout << "Metodo: " << req.method << "\n";
      std::cout << "Caminho (Path): " << req.path << "\n";
      std::cout << "============================================\n";
      });

    // As rotas explícitas do Azure (se houver fallback)
    auto chatHandler = [&](const httplib::Request& req, httplib::Response& res) {
      handler.HandleRequest(req, res);
      };

    svr.Post("/v1/chat/completions", chatHandler);
    svr.Post("/chat/completions", chatHandler);

    // --- NOVO: Forwarder Transparente Universal (Trata a sanitização bruta) ---
    auto transparentForwarder = [&](const httplib::Request& req, httplib::Response& res) {
      std::cout << "\n[CLI TRANSPARENTE] Roteando " << req.method << " " << req.path << " direto para o GitHub...\n";

      httplib::SSLClient cli("api.githubcopilot.com");
      cli.set_read_timeout(120, 0);

      // Copia os headers, removendo interferências
      httplib::Headers headers;
      for (const auto& h : req.headers) {
        std::string key = h.first;
        std::transform(key.begin(), key.end(), key.begin(), ::tolower);
        if (key != "host" && key != "content-length" && key != "accept-encoding") {
          headers.emplace(h.first, h.second);
        }
      }

      std::string body = req.body;

      // SANITIZAÇÃO BRUTA: Aplica máscara em todo o JSON, ignorando a estrutura
      if (req.method == "POST" && !body.empty()) {
        body = sanitizer.SanitizeString(body);

        // REMOVIDO: A forçação de "stream: false" que quebrava o CLI.
        // Agora respeitamos o que o CLI pediu (SSE Stream).

        std::cout << "     [->] Payload (RAW) mascarado com sucesso.\n";
      }

      auto process_response = [&](auto& apiRes) {
        if (apiRes) {
          std::cout << "     [<-] Status da Nuvem: HTTP " << apiRes->status << "\n";
          std::string print_body = apiRes->body;
          if (print_body.length() > 300) print_body = print_body.substr(0, 300) + "... [truncado]";
          std::cout << "     [<-] Resposta da Nuvem: " << print_body << "\n";

          res.status = apiRes->status;
          std::string res_body = apiRes->body;

          // RESTAURAÇÃO BRUTA
          if (!res_body.empty()) {
            res_body = sanitizer.RestoreString(res_body);
          }

          // DEVOLVE OS HEADERS ORIGINAIS PARA O CLI!
          for (auto& h : apiRes->headers) {
            std::string key = h.first;
            std::transform(key.begin(), key.end(), key.begin(), ::tolower);

            // REMOVIDO "content-type" daqui para não duplicar com o res.set_content e crashar o Node.js do CLI
            if (key != "content-encoding" && key != "content-length" && key != "transfer-encoding" && key != "content-type") {
              res.set_header(h.first, h.second);
            }
          }

          std::string res_ctype = apiRes->has_header("Content-Type") ? apiRes->get_header_value("Content-Type") : "application/json";
          res.set_content(res_body, res_ctype.c_str());
        }
        else {
          std::cout << "     [ERRO DE REDE] Falha ao comunicar com a Nuvem. Codigo de erro httplib: " << static_cast<int>(apiRes.error()) << "\n";
          res.status = 502;
          res.set_content("{\"error\": \"Proxy Forwarding Failed\"}", "application/json");
        }
        };

      if (req.method == "GET") {
        auto apiRes = cli.Get(req.path.c_str(), headers);
        process_response(apiRes);
      }
      else if (req.method == "POST") {
        std::string ctype = req.has_header("Content-Type") ? req.get_header_value("Content-Type") : "application/json";
        auto apiRes = cli.Post(req.path.c_str(), headers, body, ctype.c_str());
        process_response(apiRes);
      }
      };

    // Regista explicitamente as rotas que descobrimos
    svr.Get("/models", transparentForwarder);
    svr.Post("/mcp/readonly", transparentForwarder);
    svr.Get("/agents/swe/internal/memory/v0/user/enabled", transparentForwarder);
    svr.Post("/responses", transparentForwarder);

    // O CATCH-ALL (Rede de Segurança Universal)
    svr.set_error_handler([&](const httplib::Request& req, httplib::Response& res) {
      if (req.method == "CONNECT") {
        std::cout << "\n[ERRO DE ROTA] Tentativa CONNECT rejeitada: " << req.path << "\n";
        res.status = 405;
        return;
      }
      std::cout << "\n[CATCH-ALL] Rota nao mapeada detectada (" << req.path << "). Redirecionando...\n";
      transparentForwarder(req, res);
      });

    svr.Get("/ping", [](const httplib::Request&, httplib::Response& res) {
      res.set_content("Proxy vivo!", "text/plain");
      });

    Logger::Info("Proxy SUPER DEBUG pronto na porta " + std::to_string(config.GetPort()));

    if (!svr.listen("0.0.0.0", config.GetPort())) {
      Logger::Error("Falha ao abrir a porta " + std::to_string(config.GetPort()));
      return 1;
    }
  }
  catch (const std::exception& e)
  {
    Logger::Error(e.what());
    return 1;
  }
  return 0;
}