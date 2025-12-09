import React, { useState, useRef } from "react";
import { createRoot } from "react-dom/client";
import { Lock, Unlock, FileText, Download, Upload, Copy, RefreshCw, Terminal } from "lucide-react";

// --- PYTHON SCRIPT CONTENT ---
// This string contains the exact python script requested by the user.
const PYTHON_SCRIPT_CONTENT = `import random
import string
import json
import os

def generate_random_name(length=4):
    return ''.join(random.choices(string.ascii_lowercase, k=length))

def create_key_map():
    # Define the character set (approx 95 printable characters)
    # User requested approx 93, we use printable non-whitespace + space usually 32-126
    chars = [chr(i) for i in range(32, 127)] 
    
    # 7-bit binary means 2^7 = 128 possibilities (0000000 to 1111111)
    # We create all 128 binary strings of length 7
    all_binaries = [format(i, '07b') for i in range(128)]
    
    # Shuffle the binaries to create a random cipher
    random.shuffle(all_binaries)
    
    # Map characters to the first N binaries
    # The remaining binaries are "void" (unassigned)
    key_map = {}
    for char, binary in zip(chars, all_binaries):
        key_map[char] = binary
        
    return key_map

def encrypt_message():
    print("--- ENCRYPT MODE ---")
    message = input("Enter message (max 1000 chars): ")
    
    if len(message) > 1000:
        print("Message too long! Truncating to 1000 characters.")
        message = message[:1000]

    key_map = create_key_map()
    
    encrypted_parts = []
    for char in message:
        if char in key_map:
            encrypted_parts.append(key_map[char])
        else:
            # Handle characters outside our set if necessary, or ignore
            pass
            
    cipher_text = "".join(encrypted_parts)
    
    # Generate filenames
    base_name = generate_random_name()
    key_filename = f"{base_name}.key"
    text_filename = f"{base_name}.txt"
    
    # Save Key
    with open(key_filename, 'w') as f:
        json.dump(key_map, f, indent=2)
        
    # Save Cipher Text
    with open(text_filename, 'w') as f:
        f.write(cipher_text)
        
    print(f"\\nSuccess! Files created:")
    print(f"Key: {key_filename}")
    print(f"Cipher: {text_filename}")
    print(f"Cipher Text Preview: {cipher_text[:50]}...")

def decrypt_message():
    print("--- DECRYPT MODE ---")
    key_path = input("Enter the path to the .key file: ")
    text_path = input("Enter the path to the text file (same name usually): ")
    
    if not os.path.exists(key_path) or not os.path.exists(text_path):
        print("Error: Files not found.")
        return

    try:
        with open(key_path, 'r') as f:
            key_map = json.load(f)
            
        with open(text_path, 'r') as f:
            cipher_text = f.read().strip()
            
        # Create reverse map: binary -> char
        reverse_map = {v: k for k, v in key_map.items()}
        
        # Parse 7-bit chunks
        # We assume the file is a continuous string of 0s and 1s
        chunk_size = 7
        decrypted_chars = []
        
        for i in range(0, len(cipher_text), chunk_size):
            chunk = cipher_text[i:i+chunk_size]
            if len(chunk) == chunk_size:
                if chunk in reverse_map:
                    decrypted_chars.append(reverse_map[chunk])
                else:
                    decrypted_chars.append("?") # Void/Unknown
                    
        print(f"\\nDecrypted Message:\\n{''.join(decrypted_chars)}")
        
    except Exception as e:
        print(f"An error occurred: {e}")

def main():
    while True:
        print("\\n1. Encrypt Message")
        print("2. Decrypt Message")
        print("3. Exit")
        choice = input("Choose an option: ")
        
        if choice == '1':
            encrypt_message()
        elif choice == '2':
            decrypt_message()
        elif choice == '3':
            break
        else:
            print("Invalid choice.")

if __name__ == "__main__":
    main()
`;

// --- REACT APP LOGIC ---

type KeyMap = Record<string, string>;

const MAX_CHARS = 1000;
const BINARY_LENGTH = 7;

function App() {
  const [activeTab, setActiveTab] = useState<"encrypt" | "decrypt" | "script">("encrypt");
  
  // Encrypt State
  const [inputText, setInputText] = useState("");
  const [generatedKey, setGeneratedKey] = useState<KeyMap | null>(null);
  const [cipherText, setCipherText] = useState("");
  const [fileBaseName, setFileBaseName] = useState("");

  // Decrypt State
  const [decryptKeyFile, setDecryptKeyFile] = useState<File | null>(null);
  const [decryptTextFile, setDecryptTextFile] = useState<File | null>(null);
  const [decryptedOutput, setDecryptedOutput] = useState("");
  const [decryptError, setDecryptError] = useState("");

  const generateRandomName = () => {
    const chars = "abcdefghijklmnopqrstuvwxyz";
    let result = "";
    for (let i = 0; i < 4; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  };

  const handleEncrypt = () => {
    if (!inputText) return;

    // 1. Generate Key Map
    const chars = [];
    // Printable ASCII range 32-126
    for (let i = 32; i < 127; i++) {
      chars.push(String.fromCharCode(i));
    }

    // Generate all 128 7-bit binaries
    const allBinaries = [];
    for (let i = 0; i < 128; i++) {
      allBinaries.push(i.toString(2).padStart(BINARY_LENGTH, "0"));
    }

    // Shuffle binaries
    for (let i = allBinaries.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [allBinaries[i], allBinaries[j]] = [allBinaries[j], allBinaries[i]];
    }

    // Map
    const newKeyMap: KeyMap = {};
    chars.forEach((char, index) => {
      if (index < allBinaries.length) {
        newKeyMap[char] = allBinaries[index];
      }
    });

    // 2. Encrypt Text
    let encoded = "";
    for (let i = 0; i < inputText.length; i++) {
      const char = inputText[i];
      if (newKeyMap[char]) {
        encoded += newKeyMap[char];
      }
    }

    setGeneratedKey(newKeyMap);
    setCipherText(encoded);
    setFileBaseName(generateRandomName());
  };

  const downloadFiles = () => {
    if (!generatedKey || !cipherText || !fileBaseName) return;

    // Download Key
    const keyBlob = new Blob([JSON.stringify(generatedKey, null, 2)], { type: "application/json" });
    const keyUrl = URL.createObjectURL(keyBlob);
    const keyLink = document.createElement("a");
    keyLink.href = keyUrl;
    keyLink.download = `${fileBaseName}.key`; // Actually json content, but extension .key as requested
    document.body.appendChild(keyLink);
    keyLink.click();
    document.body.removeChild(keyLink);

    // Download Cipher Text
    const textBlob = new Blob([cipherText], { type: "text/plain" });
    const textUrl = URL.createObjectURL(textBlob);
    const textLink = document.createElement("a");
    textLink.href = textUrl;
    textLink.download = `${fileBaseName}.txt`;
    document.body.appendChild(textLink);
    textLink.click();
    document.body.removeChild(textLink);
  };

  const handleDecrypt = async () => {
    setDecryptError("");
    setDecryptedOutput("");

    if (!decryptKeyFile || !decryptTextFile) {
      setDecryptError("Please upload both the Key file and the Cipher Text file.");
      return;
    }

    try {
      // Read Key
      const keyText = await decryptKeyFile.text();
      const keyMap = JSON.parse(keyText);

      // Read Cipher
      const cipher = (await decryptTextFile.text()).trim();

      // Invert Key Map
      const reverseMap: Record<string, string> = {};
      Object.entries(keyMap).forEach(([char, binary]) => {
        reverseMap[binary as string] = char;
      });

      // Decrypt
      let result = "";
      for (let i = 0; i < cipher.length; i += BINARY_LENGTH) {
        const chunk = cipher.slice(i, i + BINARY_LENGTH);
        if (chunk.length === BINARY_LENGTH) {
          if (reverseMap[chunk]) {
            result += reverseMap[chunk];
          } else {
            result += ""; // Unknown/Void
          }
        }
      }

      setDecryptedOutput(result);

    } catch (err) {
      console.error(err);
      setDecryptError("Failed to process files. Ensure the Key file is valid JSON and matches the cipher.");
    }
  };

  const copyScript = () => {
    navigator.clipboard.writeText(PYTHON_SCRIPT_CONTENT);
  };

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-4 md:p-8 flex flex-col items-center">
      <div className="max-w-4xl w-full space-y-8">
        
        {/* Header */}
        <header className="text-center space-y-2">
          <h1 className="text-3xl md:text-4xl font-bold bg-gradient-to-r from-emerald-400 to-cyan-400 bg-clip-text text-transparent">
            7-Bit Cipher Engine
          </h1>
          <p className="text-slate-400">Secure binary transposition with dynamic keys</p>
        </header>

        {/* Navigation */}
        <div className="flex justify-center space-x-4 bg-slate-800 p-2 rounded-xl border border-slate-700 w-fit mx-auto">
          <button
            onClick={() => setActiveTab("encrypt")}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-all ${
              activeTab === "encrypt" 
              ? "bg-emerald-600 text-white shadow-lg shadow-emerald-900/50" 
              : "hover:bg-slate-700 text-slate-400"
            }`}
          >
            <Lock size={18} />
            <span>Encrypt</span>
          </button>
          <button
            onClick={() => setActiveTab("decrypt")}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-all ${
              activeTab === "decrypt" 
              ? "bg-cyan-600 text-white shadow-lg shadow-cyan-900/50" 
              : "hover:bg-slate-700 text-slate-400"
            }`}
          >
            <Unlock size={18} />
            <span>Decrypt</span>
          </button>
          <button
            onClick={() => setActiveTab("script")}
            className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-all ${
              activeTab === "script" 
              ? "bg-purple-600 text-white shadow-lg shadow-purple-900/50" 
              : "hover:bg-slate-700 text-slate-400"
            }`}
          >
            <Terminal size={18} />
            <span>Python Script</span>
          </button>
        </div>

        {/* Content Area */}
        <main className="bg-slate-800 rounded-2xl border border-slate-700 shadow-xl overflow-hidden min-h-[400px]">
          
          {/* ENCRYPT TAB */}
          {activeTab === "encrypt" && (
            <div className="p-6 md:p-8 space-y-6">
              <div className="space-y-2">
                <label className="text-sm font-medium text-slate-400 flex justify-between">
                  <span>Input Message</span>
                  <span className={`${inputText.length > MAX_CHARS ? 'text-red-400' : 'text-slate-500'}`}>
                    {inputText.length} / {MAX_CHARS}
                  </span>
                </label>
                <textarea
                  className="w-full h-32 bg-slate-900 border border-slate-700 rounded-xl p-4 text-slate-100 focus:ring-2 focus:ring-emerald-500 focus:border-transparent outline-none resize-none transition-all mono"
                  placeholder="Type your message here..."
                  value={inputText}
                  onChange={(e) => setInputText(e.target.value.slice(0, MAX_CHARS))}
                />
              </div>

              <div className="flex justify-end">
                <button
                  onClick={handleEncrypt}
                  disabled={!inputText}
                  className="flex items-center space-x-2 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed text-white px-6 py-2 rounded-lg font-medium transition-colors"
                >
                  <RefreshCw size={18} />
                  <span>Generate Cipher & Key</span>
                </button>
              </div>

              {cipherText && generatedKey && (
                <div className="space-y-4 animate-in fade-in slide-in-from-bottom-4 duration-500">
                  <div className="p-4 bg-slate-900 rounded-xl border border-slate-700 relative group">
                     <label className="text-xs font-semibold text-emerald-500 uppercase tracking-wider mb-2 block">
                       Cipher Output ({fileBaseName}.txt)
                     </label>
                     <p className="mono text-xs text-slate-400 break-all leading-relaxed max-h-32 overflow-y-auto">
                       {cipherText}
                     </p>
                  </div>

                  <div className="flex items-center justify-between bg-slate-700/50 p-4 rounded-xl border border-slate-700">
                    <div className="flex flex-col">
                       <span className="text-sm font-medium text-white">Files Ready</span>
                       <span className="text-xs text-slate-400">
                         {fileBaseName}.key & {fileBaseName}.txt
                       </span>
                    </div>
                    <button
                      onClick={downloadFiles}
                      className="flex items-center space-x-2 bg-slate-700 hover:bg-slate-600 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors border border-slate-600"
                    >
                      <Download size={16} />
                      <span>Download Both</span>
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* DECRYPT TAB */}
          {activeTab === "decrypt" && (
            <div className="p-6 md:p-8 space-y-8">
              <div className="grid md:grid-cols-2 gap-6">
                
                {/* Key File Upload */}
                <div className="space-y-2">
                  <label className="text-sm font-medium text-slate-400">Key File (.key)</label>
                  <div className={`relative border-2 border-dashed rounded-xl p-6 text-center transition-all ${
                    decryptKeyFile ? "border-cyan-500 bg-cyan-900/10" : "border-slate-700 hover:border-cyan-500/50 hover:bg-slate-700/30"
                  }`}>
                    <input
                      type="file"
                      accept=".key,.json"
                      onChange={(e) => setDecryptKeyFile(e.target.files?.[0] || null)}
                      className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                    />
                    <FileText className={`mx-auto mb-2 ${decryptKeyFile ? "text-cyan-400" : "text-slate-500"}`} size={24} />
                    <span className="text-sm block truncate max-w-full px-2">
                      {decryptKeyFile ? decryptKeyFile.name : "Drop .key file here"}
                    </span>
                  </div>
                </div>

                {/* Cipher File Upload */}
                <div className="space-y-2">
                  <label className="text-sm font-medium text-slate-400">Cipher File (.txt)</label>
                  <div className={`relative border-2 border-dashed rounded-xl p-6 text-center transition-all ${
                    decryptTextFile ? "border-cyan-500 bg-cyan-900/10" : "border-slate-700 hover:border-cyan-500/50 hover:bg-slate-700/30"
                  }`}>
                    <input
                      type="file"
                      accept=".txt"
                      onChange={(e) => setDecryptTextFile(e.target.files?.[0] || null)}
                      className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                    />
                    <FileText className={`mx-auto mb-2 ${decryptTextFile ? "text-cyan-400" : "text-slate-500"}`} size={24} />
                    <span className="text-sm block truncate max-w-full px-2">
                      {decryptTextFile ? decryptTextFile.name : "Drop .txt file here"}
                    </span>
                  </div>
                </div>
              </div>

              <div className="flex justify-center">
                <button
                  onClick={handleDecrypt}
                  disabled={!decryptKeyFile || !decryptTextFile}
                  className="flex items-center space-x-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed text-white px-8 py-3 rounded-lg font-medium transition-colors shadow-lg shadow-cyan-900/20"
                >
                  <Unlock size={18} />
                  <span>Decrypt Message</span>
                </button>
              </div>

              {decryptError && (
                 <div className="p-4 bg-red-900/20 border border-red-800 text-red-200 rounded-lg text-sm text-center">
                   {decryptError}
                 </div>
              )}

              {decryptedOutput && (
                <div className="space-y-2 animate-in fade-in zoom-in-95 duration-300">
                  <label className="text-xs font-semibold text-cyan-500 uppercase tracking-wider">Decrypted Result</label>
                  <div className="w-full min-h-[120px] bg-slate-900 border border-cyan-500/30 rounded-xl p-4 text-cyan-50 shadow-inner mono">
                    {decryptedOutput}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* SCRIPT TAB */}
          {activeTab === "script" && (
            <div className="flex flex-col h-full max-h-[600px]">
               <div className="bg-slate-900 p-4 border-b border-slate-700 flex justify-between items-center">
                 <div className="flex items-center space-x-2 text-slate-300">
                   <Terminal size={16} />
                   <span className="text-sm font-mono">cipher_tool.py</span>
                 </div>
                 <button
                   onClick={copyScript}
                   className="flex items-center space-x-1 text-xs bg-slate-800 hover:bg-slate-700 text-slate-300 px-3 py-1.5 rounded border border-slate-600 transition-colors"
                 >
                   <Copy size={12} />
                   <span>Copy Code</span>
                 </button>
               </div>
               <div className="flex-1 overflow-auto p-4 bg-[#0d1117]">
                 <pre className="text-xs md:text-sm font-mono text-slate-300 leading-relaxed whitespace-pre">
                   <code>{PYTHON_SCRIPT_CONTENT}</code>
                 </pre>
               </div>
            </div>
          )}

        </main>
      </div>
    </div>
  );
}

const container = document.getElementById("root");
if (container) {
  const root = createRoot(container);
  root.render(<App />);
}
