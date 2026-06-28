#pragma once

#include <string>

std::string sha256File(const std::string& path);
std::string sha256Data(const std::string& data);

int generateKeypair(const std::string& priv_path, const std::string& pub_path);
int signFile(const std::string& file_path, const std::string& key_path, const std::string& sig_path);
bool verifyFile(const std::string& file_path, const std::string& sig_path, const std::string& pub_key_path);
bool verifyFileWithKey(const std::string& file_path, const std::string& sig_path, const std::string& pub_key_pem);
