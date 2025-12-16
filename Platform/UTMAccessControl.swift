//
// Copyright © 2024 osy. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

import Foundation

/// Handles access control for UTM
final class UTMAccessControl {
    
    /// List of blocked email addresses
    private static let blockedEmails: Set<String> = [
        "hyperboreanephilim@icloud.com",
        "hyperboreatanael@icloud.com"
    ]
    
    /// Check if the current user is blocked from accessing the application
    /// - Returns: true if access should be denied, false otherwise
    static func isAccessBlocked() -> Bool {
        // Get the user's Apple ID/iCloud email
        #if os(iOS) || os(visionOS)
        if let email = getiCloudEmail() {
            return blockedEmails.contains(email.lowercased())
        }
        #elseif os(macOS)
        if let email = getAppleIDEmail() {
            return blockedEmails.contains(email.lowercased())
        }
        #endif
        return false
    }
    
    #if os(iOS) || os(visionOS)
    /// Get the iCloud email for iOS/visionOS
    private static func getiCloudEmail() -> String? {
        if let ubiquityToken = FileManager.default.ubiquityIdentityToken {
            // Try to get the email from UserDefaults which may have been cached
            if let cachedEmail = UserDefaults.standard.string(forKey: "AppleIDEmail") {
                return cachedEmail
            }
            // Try to get from NSUbiquitousKeyValueStore
            if let email = NSUbiquitousKeyValueStore.default.string(forKey: "email") {
                return email
            }
        }
        return nil
    }
    #endif
    
    #if os(macOS)
    /// Get the Apple ID email for macOS
    private static func getAppleIDEmail() -> String? {
        // Try to get from system
        let task = Process()
        task.launchPath = "/usr/bin/dscl"
        task.arguments = [".", "-read", NSHomeDirectory(), "dsAttrTypeNative:AppleID"]
        
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = Pipe()
        
        do {
            try task.run()
            task.waitUntilExit()
            
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            if let output = String(data: data, encoding: .utf8) {
                // Parse the output to extract email
                let lines = output.components(separatedBy: .newlines)
                for line in lines {
                    if line.contains("@") {
                        let components = line.components(separatedBy: .whitespaces)
                        for component in components {
                            if component.contains("@") && component.contains(".") {
                                return component.trimmingCharacters(in: .whitespaces)
                            }
                        }
                    }
                }
            }
        } catch {
            // Failed to get email, continue
        }
        
        // Alternative: Check NSUserName and try to derive from common patterns
        let userName = NSUserName()
        
        // Try to get from defaults domain
        if let defaults = UserDefaults(suiteName: "com.apple.icloud") {
            if let email = defaults.string(forKey: "AppleID") {
                return email
            }
        }
        
        return nil
    }
    #endif
    
    /// Block access and terminate the application
    static func blockAccess() {
        #if os(iOS) || os(visionOS)
        // On iOS, we show an alert and exit
        DispatchQueue.main.async {
            exit(0)
        }
        #elseif os(macOS)
        // On macOS, terminate the application
        DispatchQueue.main.async {
            NSApplication.shared.terminate(nil)
        }
        #endif
    }
}
