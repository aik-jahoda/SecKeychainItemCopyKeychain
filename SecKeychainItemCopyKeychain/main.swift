//
//  main.swift
//  SecKeychainItemCopyKeychain
//
//  Created by Jan Jahoda on 18/01/2021.
//

import Foundation
import Security

let path = "~/my.keychain"
var keychain: SecKeychain?

print("==============================================================")
var status = SecKeychainCreate(path, 0, "", false, nil, &keychain)
print("Create Keychain finished with status: \(status) \(SecCopyErrorMessageString(status, nil) ?? "" as CFString)")

if status == OSStatus(errSecDuplicateKeychain) {
    print("==============================================================")
    status = SecKeychainOpen(path, &keychain)
    print("Open Keychain finished with status: \(status) \(SecCopyErrorMessageString(status, nil) ?? "" as CFString)")
}

let keychainItem = [
    kSecValueData: "Pullip2020".data(using: .utf8)!,
    kSecAttrAccount: "andyibanez",
    kSecAttrServer: "pullipstyle.com",
    kSecClass: kSecClassInternetPassword,
    kSecUseKeychain: keychain!,
    kSecReturnAttributes: true
] as CFDictionary

var ref: AnyObject?

let query = [
    kSecClass: kSecClassInternetPassword,
    kSecAttrServer: "pullipstyle.com",
    kSecReturnAttributes: true,
    kSecReturnData: true
] as CFDictionary

print("==============================================================")
status = SecItemCopyMatching(query, &ref)
print("SecItemCopyMatching finished with status: \(status) \(SecCopyErrorMessageString(status, nil) ?? "" as CFString)")

if status != 0 || ref == nil {
    print("==============================================================")
    status = SecItemAdd(keychainItem, &ref)
    print("Add Item finished with status: \(status) \(SecCopyErrorMessageString(status, nil) ?? "" as CFString)")
}
print("==============================================================")
if ref != nil {
    let result = ref as! NSDictionary
    print("Returned attributes:")
    result.forEach { key, value in
        print("\(key): \(value)")
    }
}

print("==============================================================")

var format : UnsafeMutablePointer<SecExternalFormat>? = nil
var itemType : UnsafeMutablePointer<SecExternalItemType>? = nil
var outItems: CFArray? = nil
var keyParams = SecItemImportExportKeyParameters()
keyParams.version = UInt32(SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION)
//    keyParams.passphrase = "ExportImportPassphrase" as CFString
let fileNameOrExtension = "test1.cer" as CFString
let importKeychain : SecKeychain? = nil
let importedData: CFData = FileManager().contents(atPath: "test1.cer")! as CFData
let flags = SecItemImportExportFlags.pemArmour

var test1Item :SecKeychainItem? = nil
status = ImportCertificate(fileName: "test1.cer", certificate: &test1Item, importKeychain: nil)

var test2Item :SecKeychainItem? = nil
status = ImportCertificate(fileName: "test2.cer", certificate: &test2Item, importKeychain: nil)

print("==============================================================")

var pKeychainOut: SecKeychain? = nil;
SecKeychainItemCopyKeychain((test1Item)!, &pKeychainOut);
print("SecKeychainItemCopyKeychain finished \(String(describing: pKeychainOut)) with status: \(status) \(SecCopyErrorMessageString(status, nil) ?? "" as CFString)")

SecKeychainItemCopyKeychain((test2Item)!, &pKeychainOut);
print("SecKeychainItemCopyKeychain finished \(String(describing: pKeychainOut)) with status: \(status) \(SecCopyErrorMessageString(status, nil) ?? "" as CFString)")

print(" -25294 = \(SecCopyErrorMessageString(-25294, nil) ?? "" as CFString)")

func ImportCertificate(fileName: String, certificate: UnsafeMutablePointer<SecKeychainItem?>, importKeychain: SecKeychain?  ) -> OSStatus {
    let format : UnsafeMutablePointer<SecExternalFormat>? = nil
    let itemType : UnsafeMutablePointer<SecExternalItemType>? = nil
    var outItems: CFArray? = nil
    var keyParams = SecItemImportExportKeyParameters()
    keyParams.version = UInt32(SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION)
    let fileNameOrExtension = fileName as CFString
    let importedData: CFData = FileManager().contents(atPath:fileName)! as CFData
    
    let status = SecItemImport(
        importedData,
        fileNameOrExtension,
        format,
        itemType,
        SecItemImportExportFlags.pemArmour,
        &keyParams,
        importKeychain,
        &outItems)
    
    
    print("Imported \(fileName) \(String(describing: format)) \(String(describing: itemType)) with status: \(status) \(SecCopyErrorMessageString(status, nil) ?? "" as CFString)")
    
    certificate.initialize(to: nil)
    
    if (outItems != nil){
        let items = outItems as [AnyObject]? ?? []
        for element in items {
            
            print("element = \(element)")
        }
        
        if (items.count > 0)
        {
            certificate.initialize(to: (items[0] as! SecKeychainItem));
        }
    }
    
    return status
}
