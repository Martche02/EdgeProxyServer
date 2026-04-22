#pragma once
#define CPPHTTPLIB_OPENSSL_SUPPORT

#pragma comment(lib, "Crypt32.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")

#include "httplib.h"
#include "nlohmann/json.hpp"
#include <string>
#include <unordered_map>
#include <vector>
#include <regex>

class Logger
{
public:
  static void Info(const std::string& msg);
  static void Error(const std::string& msg);
  static void Debug(const std::string& msg);
};

class Config
{
private:
  std::string _apiKey;
  int _port;
  std::string _vaultPath;
  std::string _targetModel;
public:
  void LoadFromEnvironment();
  const std::string& GetApiKey() const { return _apiKey; }
  int GetPort() const { return _port; }
  const std::string& GetVaultPath() const { return _vaultPath; }
  const std::string& GetTargetModel() const { return _targetModel; }
};

class IpVault
{
private:
  std::unordered_map<std::string, std::string> _realToMask;
  std::unordered_map<std::string, std::string> _maskToReal;
  std::vector<std::string> _sortedRealKeys;
  std::vector<std::string> _sortedMaskKeys;
public:
  void LoadFromFile(const std::string& filepath);
  const std::vector<std::string>& GetSortedRealKeys() const { return _sortedRealKeys; }
  const std::vector<std::string>& GetSortedMaskKeys() const { return _sortedMaskKeys; }
  const std::string& GetMasked(const std::string& real) const { return _realToMask.at(real); }
  const std::string& GetReal(const std::string& mask) const { return _maskToReal.at(mask); }
};

class Sanitizer
{
private:
  struct ReplaceRule { std::regex pattern; std::string replacement; };
  std::vector<ReplaceRule> _sanitizeRules;
  std::vector<ReplaceRule> _restoreRules;
public:
  void InitializeRules(const IpVault& vault);
  std::string SanitizeString(const std::string& text) const;
  std::string RestoreString(const std::string& text) const;
  void SanitizeJsonPayload(nlohmann::json& payload, const std::string& targetModel) const;
  void RestoreJsonPayload(nlohmann::json& payload) const;
};

class OpenAiClient
{
private:
  std::string _apiKey;
  const std::string _host = "models.inference.ai.azure.com";
public:
  explicit OpenAiClient(const std::string& key);
  httplib::Result PostChatCompletion(const std::string& jsonBody) const;
};

class CompletionHandler
{
private:
  const Sanitizer& _sanitizer;
  const OpenAiClient& _llmClient;
  std::string _targetModel;
public:
  CompletionHandler(const Sanitizer& s, const OpenAiClient& c, const std::string& model);
  void HandleRequest(const httplib::Request& req, httplib::Response& res) const;
};