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

print("==============================================================")
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
