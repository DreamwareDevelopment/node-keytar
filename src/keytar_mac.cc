#include <Security/Security.h>
#include "keytar.h"
#include "credentials.h"


namespace keytar {

/**
 * Converts a CFString to a std::string
 *
 * This either uses CFStringGetCStringPtr or (if that fails)
 * CFStringGetCString, trying to be as efficient as possible.
 */
const std::string CFStringToStdString(CFStringRef cfstring) {
  const char* cstr = CFStringGetCStringPtr(cfstring, kCFStringEncodingUTF8);

  if (cstr != NULL) {
    return std::string(cstr);
  }

  CFIndex length = CFStringGetLength(cfstring);
  // Worst case: 2 bytes per character + NUL
  CFIndex cstrPtrLen = length * 2 + 1;
  char* cstrPtr = static_cast<char*>(malloc(cstrPtrLen));

  Boolean result = CFStringGetCString(cfstring,
                                      cstrPtr,
                                      cstrPtrLen,
                                      kCFStringEncodingUTF8);

  std::string stdstring;
  if (result) {
    stdstring = std::string(cstrPtr);
  }

  free(cstrPtr);

  return stdstring;
}

/**
 * Converts a std::string to a CFString
 */
CFStringRef StdStringToCFString(std::string stdstring) {
  const char* cstr = stdstring.c_str();
  CFStringRef cfString;
  cfString = CFStringCreateWithCString(NULL, cstr, kCFStringEncodingUTF8);
  return cfString;
}

const std::string errorStatusToString(OSStatus status) {
  std::string errorStr;
  CFStringRef errorMessageString = SecCopyErrorMessageString(status, NULL);

  const char* errorCStringPtr = CFStringGetCStringPtr(errorMessageString,
                                                      kCFStringEncodingUTF8);
  if (errorCStringPtr) {
    errorStr = std::string(errorCStringPtr);
  } else {
    errorStr = std::string("An unknown error occurred.");
  }

  CFRelease(errorMessageString);
  return errorStr;
}

KEYTAR_OP_RESULT UpdateSecret(const std::string& service,
                           const std::string& account,
                           const std::string& secret,
                           std::string* error) {
  CFStringRef serviceStr = StdStringToCFString(service);
  CFRetain(serviceStr);
  CFStringRef accountStr = StdStringToCFString(account);
  CFRetain(accountStr);
  CFStringRef secretStr = StdStringToCFString(secret);
  CFRetain(secretStr);

  CFStringRef queryKeys[3];
  CFStringRef queryValues[3];
  queryKeys[0] = kSecClass;
  queryKeys[1] = kSecAttrServer;
  queryKeys[2] = kSecAttrAccount;
  queryValues[0] = kSecClassInternetPassword;
  queryValues[1] = serviceStr;
  queryValues[2] = accountStr;

  CFDictionaryRef query = CFDictionaryCreate(
    NULL,
    (const void **)queryKeys,
    (const void **)queryValues,
    3,
    &kCFCopyStringDictionaryKeyCallBacks,
    &kCFTypeDictionaryValueCallBacks);
  CFRetain(query);
  CFRelease(serviceStr);
  CFRelease(accountStr);

  CFDataRef secretData = CFStringCreateExternalRepresentation(
    NULL,
    secretStr,
    kCFStringEncodingUTF8,
    0);
  CFRelease(secretStr);
  CFStringRef attributeKeys[1];
  CFTypeRef attributeValues[1];
  attributeKeys[0] = kSecValueData;
  attributeValues[0] = secretData;

  CFDictionaryRef attributes = CFDictionaryCreate(
    NULL,
    (const void **)attributeKeys,
    (const void **)attributeValues,
    2,
    &kCFCopyStringDictionaryKeyCallBacks,
    &kCFTypeDictionaryValueCallBacks);
  CFRetain(attributes);
  OSStatus status = SecItemUpdate(query, attributes);
  CFRelease(attributes);
  CFRelease(query);
  if (status == errSecItemNotFound) {
    return FAIL_NONFATAL;
  } else if (status != errSecSuccess) {
    *error = errorStatusToString(status);
    return FAIL_ERROR;
  }
  return SUCCESS;
}

KEYTAR_OP_RESULT AddSecret(const std::string& service,
                           const std::string& account,
                           const std::string& secret,
                           std::string* error) {
  CFStringRef serviceStr = StdStringToCFString(service);
  CFRetain(serviceStr);
  CFStringRef accountStr = StdStringToCFString(account);
  CFRetain(accountStr);
  CFStringRef secretStr = StdStringToCFString(secret);
  CFRetain(secretStr);
  CFDataRef secretData = CFStringCreateExternalRepresentation(
    NULL,
    secretStr,
    kCFStringEncodingUTF8,
    0);
  CFRelease(secretStr);

  CFStringRef keys[4];
  CFTypeRef values[4];
  keys[0] = kSecClass;
  keys[1] = kSecAttrServer;
  keys[2] = kSecAttrAccount;
  keys[3] = kSecValueData;
  values[0] = kSecClassInternetPassword;
  values[1] = serviceStr;
  values[2] = accountStr;
  values[3] = secretData;

  CFDictionaryRef attributes = CFDictionaryCreate(
    NULL,
    (const void **)keys,
    (const void **)values,
    4,
    &kCFCopyStringDictionaryKeyCallBacks,
    &kCFTypeDictionaryValueCallBacks);
  CFRetain(attributes);
  CFRelease(serviceStr);
  CFRelease(accountStr);
  CFTypeRef result;
  OSStatus status = SecItemAdd(attributes, &result);
  CFRelease(attributes);
  if (status != errSecSuccess) {
    *error = errorStatusToString(status);
    return FAIL_ERROR;
  }
  return SUCCESS;
}

KEYTAR_OP_RESULT SetSecret(const std::string& service,
                           const std::string& account,
                           const std::string& secret,
                           std::string* error) {
  KEYTAR_OP_RESULT result = UpdateSecret(service, account, secret, error);
  if (result == FAIL_NONFATAL) {
    // This secret doesn't exist, add a new secret
    return AddSecret(service, account, secret, error);
  } else if (result == FAIL_ERROR) {
    return FAIL_ERROR;
  }
  return SUCCESS;
}

KEYTAR_OP_RESULT GetSecret(const std::string& service,
                             const std::string& account,
                             std::string* secret,
                             std::string* error) {
  CFStringRef serviceStr = StdStringToCFString(service);
  CFRetain(serviceStr);
  CFStringRef accountStr = StdStringToCFString(account);
  CFRetain(accountStr);

  CFStringRef keys[5];
  CFTypeRef values[5];
  keys[0] = kSecClass;
  keys[1] = kSecAttrServer;
  keys[2] = kSecAttrAccount;
  keys[3] = kSecMatchLimit;
  keys[4] = kSecReturnData;
  values[0] = kSecClassInternetPassword;
  values[1] = serviceStr;
  values[2] = accountStr;
  values[3] = kSecMatchLimitOne;
  values[4] = kCFBooleanTrue;

  CFDictionaryRef query = CFDictionaryCreate(
    NULL,
    (const void **)keys,
    (const void **)values,
    5,
    &kCFCopyStringDictionaryKeyCallBacks,
    &kCFTypeDictionaryValueCallBacks);
  CFRetain(query);
  CFRelease(serviceStr);
  CFRelease(accountStr);
  CFTypeRef item;
  OSStatus status = SecItemCopyMatching(query, &item);
  CFRelease(query);

  if (status == errSecItemNotFound) {
    return FAIL_NONFATAL;
  } else if (status != errSecSuccess) {
    *error = errorStatusToString(status);
    return FAIL_ERROR;
  }

  CFStringRef result = CFStringCreateFromExternalRepresentation(
    NULL,
    (CFDataRef) item,
    kCFStringEncodingUTF8);
  CFRelease(item);
  const std::string stdResult = CFStringToStdString(result);
  CFRelease(result);
  *secret = stdResult;
  return SUCCESS;
}

KEYTAR_OP_RESULT DeleteSecret(const std::string& service,
                                const std::string& account,
                                std::string* error) {
  CFStringRef serviceStr = StdStringToCFString(service);
  CFRetain(serviceStr);
  CFStringRef accountStr = StdStringToCFString(account);
  CFRetain(accountStr);
  CFStringRef queryKeys[3];
  CFStringRef queryValues[3];
  queryKeys[0] = kSecClass;
  queryKeys[1] = kSecAttrServer;
  queryKeys[2] = kSecAttrAccount;
  queryValues[0] = kSecClassInternetPassword;
  queryValues[1] = serviceStr;
  queryValues[2] = accountStr;

  CFDictionaryRef query;
  query = CFDictionaryCreate(
    NULL,
    (const void **)queryKeys,
    (const void **)queryValues,
    3,
    &kCFCopyStringDictionaryKeyCallBacks,
    &kCFTypeDictionaryValueCallBacks);

  OSStatus status = SecItemDelete(query);
  CFRelease(query);
  if (status == errSecItemNotFound) {
    return FAIL_NONFATAL;
  }
  if (status == errSecSuccess) {
    return SUCCESS;
  }
  CFStringRef errMsg = SecCopyErrorMessageString(status, NULL);
  CFRetain(errMsg);
  *error = CFStringToStdString(errMsg);
  CFRelease(errMsg);
  return FAIL_ERROR;
}

KEYTAR_OP_RESULT AddPassword(const std::string& service,
                             const std::string& account,
                             const std::string& password,
                             std::string* error,
                             bool returnNonfatalOnDuplicate) {
  OSStatus status = SecKeychainAddGenericPassword(NULL,
                                                  service.length(),
                                                  service.data(),
                                                  account.length(),
                                                  account.data(),
                                                  password.length(),
                                                  password.data(),
                                                  NULL);

  if (status == errSecDuplicateItem && returnNonfatalOnDuplicate) {
    return FAIL_NONFATAL;
  } else if (status != errSecSuccess) {
    *error = errorStatusToString(status);
    return FAIL_ERROR;
  }

  return SUCCESS;
}

KEYTAR_OP_RESULT SetPassword(const std::string& service,
                             const std::string& account,
                             const std::string& password,
                             std::string* error) {
  KEYTAR_OP_RESULT result = AddPassword(service, account, password,
                                        error, true);
  if (result == FAIL_NONFATAL) {
    // This password already exists, delete it and try again.
    KEYTAR_OP_RESULT delResult = DeletePassword(service, account, error);
    if (delResult == FAIL_ERROR)
      return FAIL_ERROR;
    else
      return AddPassword(service, account, password, error, false);
  } else if (result == FAIL_ERROR) {
    return FAIL_ERROR;
  }

  return SUCCESS;
}

KEYTAR_OP_RESULT GetPassword(const std::string& service,
                             const std::string& account,
                             std::string* password,
                             std::string* error) {
  void *data;
  UInt32 length;
  OSStatus status = SecKeychainFindGenericPassword(NULL,
                                                   service.length(),
                                                   service.data(),
                                                   account.length(),
                                                   account.data(),
                                                   &length,
                                                   &data,
                                                   NULL);

  if (status == errSecItemNotFound) {
    return FAIL_NONFATAL;
  } else if (status != errSecSuccess) {
    *error = errorStatusToString(status);
    return FAIL_ERROR;
  }

  *password = std::string(reinterpret_cast<const char*>(data), length);
  SecKeychainItemFreeContent(NULL, data);
  return SUCCESS;
}

KEYTAR_OP_RESULT DeletePassword(const std::string& service,
                                const std::string& account,
                                std::string* error) {
  SecKeychainItemRef item;
  OSStatus status = SecKeychainFindGenericPassword(NULL,
                                                   service.length(),
                                                   service.data(),
                                                   account.length(),
                                                   account.data(),
                                                   NULL,
                                                   NULL,
                                                   &item);
  if (status == errSecItemNotFound) {
    // Item could not be found, so already deleted.
    return FAIL_NONFATAL;
  } else if (status != errSecSuccess) {
    *error = errorStatusToString(status);
    return FAIL_ERROR;
  }

  status = SecKeychainItemDelete(item);
  CFRelease(item);
  if (status != errSecSuccess) {
    *error = errorStatusToString(status);
    return FAIL_ERROR;
  }

  return SUCCESS;
}

KEYTAR_OP_RESULT FindPassword(const std::string& service,
                              std::string* password,
                              std::string* error) {
  SecKeychainItemRef item;
  void *data;
  UInt32 length;

  OSStatus status = SecKeychainFindGenericPassword(NULL,
                                                   service.length(),
                                                   service.data(),
                                                   0,
                                                   NULL,
                                                   &length,
                                                   &data,
                                                   &item);
  if (status == errSecItemNotFound) {
    return FAIL_NONFATAL;
  } else if (status != errSecSuccess) {
    *error = errorStatusToString(status);
    return FAIL_ERROR;
  }

  *password = std::string(reinterpret_cast<const char*>(data), length);
  SecKeychainItemFreeContent(NULL, data);
  CFRelease(item);
  return SUCCESS;
}

Credentials getCredentialsForItem(CFDictionaryRef item) {
  CFStringRef service = (CFStringRef) CFDictionaryGetValue(item,
                                                           kSecAttrService);
  CFStringRef account = (CFStringRef) CFDictionaryGetValue(item,
                                                           kSecAttrAccount);

  CFMutableDictionaryRef query = CFDictionaryCreateMutable(
    NULL,
    0,
    &kCFTypeDictionaryKeyCallBacks,
    &kCFTypeDictionaryValueCallBacks);

  CFDictionaryAddValue(query, kSecAttrService, service);
  CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword);
  CFDictionaryAddValue(query, kSecMatchLimit, kSecMatchLimitOne);
  CFDictionaryAddValue(query, kSecReturnAttributes, kCFBooleanTrue);
  CFDictionaryAddValue(query, kSecReturnData, kCFBooleanTrue);
  CFDictionaryAddValue(query, kSecAttrAccount, account);

  CFTypeRef result;
  OSStatus status = SecItemCopyMatching((CFDictionaryRef) query, &result);

  if (status == errSecSuccess) {
      CFDataRef passwordData = (CFDataRef) CFDictionaryGetValue(
        (CFDictionaryRef) result,
        CFSTR("v_Data"));
      CFStringRef password = CFStringCreateFromExternalRepresentation(
        NULL,
        passwordData,
        kCFStringEncodingUTF8);

      Credentials cred = Credentials(
        CFStringToStdString(account),
        CFStringToStdString(password));
      CFRelease(password);

      return cred;
  }

  return Credentials();
}

KEYTAR_OP_RESULT FindCredentials(const std::string& service,
                                 std::vector<Credentials>* credentials,
                                 std::string* error) {
  CFStringRef serviceStr = CFStringCreateWithCString(
    NULL,
    service.c_str(),
    kCFStringEncodingUTF8);

  CFMutableDictionaryRef query = CFDictionaryCreateMutable(
    NULL,
    0,
    &kCFTypeDictionaryKeyCallBacks,
    &kCFTypeDictionaryValueCallBacks);
  CFDictionaryAddValue(query, kSecClass, kSecClassGenericPassword);
  CFDictionaryAddValue(query, kSecAttrService, serviceStr);
  CFDictionaryAddValue(query, kSecMatchLimit, kSecMatchLimitAll);
  CFDictionaryAddValue(query, kSecReturnRef, kCFBooleanTrue);
  CFDictionaryAddValue(query, kSecReturnAttributes, kCFBooleanTrue);

  CFTypeRef result;
  OSStatus status = SecItemCopyMatching((CFDictionaryRef) query, &result);

  if (status == errSecSuccess) {
    CFArrayRef resultArray = (CFArrayRef) result;
    int resultCount = CFArrayGetCount(resultArray);

    for (int idx = 0; idx < resultCount; idx++) {
      CFDictionaryRef item = (CFDictionaryRef) CFArrayGetValueAtIndex(
        resultArray,
        idx);

      Credentials cred = getCredentialsForItem(item);
      credentials->push_back(cred);
    }
  } else if (status == errSecItemNotFound) {
    return FAIL_NONFATAL;
  } else {
    *error = errorStatusToString(status);
    return FAIL_ERROR;
  }


  if (result != NULL) {
    CFRelease(result);
  }

  CFRelease(query);

  return SUCCESS;
}

}  // namespace keytar
