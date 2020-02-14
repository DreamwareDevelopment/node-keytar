// Definitions by: Milan Burda <https://github.com/miniak>, Brendan Forster <https://github.com/shiftkey>, Hari Juturu <https://github.com/juturu>
// Adapted from DefinitelyTyped: https://github.com/DefinitelyTyped/DefinitelyTyped/blob/master/types/keytar/index.d.ts

/**
 * Get the stored secret for the service and account.
 *
 * @param service The string service name.
 * @param account The string account name.
 *
 * @returns A promise for the secret string.
 */
export declare function getSecret(service: string, account: string): Promise<string | null>;

/**
 * Add the secret for the service and account to the keychain.
 *
 * @param service The string service name.
 * @param account The string account name.
 * @param secret The string secret.
 *
 * @returns A promise for the set secret completion.
 */
export declare function setSecret(service: string, account: string, secret: string): Promise<void>;

/**
 * Delete the stored secret for the service and account.
 *
 * @param service The string service name.
 * @param account The string account name.
 *
 * @returns A promise for the deletion status. True on success.
 */
export declare function deleteSecret(service: string, account: string): Promise<boolean>;

/**
 * Get the stored password for the service and account.
 *
 * @param service The string service name.
 * @param account The string account name.
 *
 * @returns A promise for the password string.
 */
export declare function getPassword(service: string, account: string): Promise<string | null>;

/**
 * Add the password for the service and account to the keychain.
 *
 * @param service The string service name.
 * @param account The string account name.
 * @param password The string password.
 *
 * @returns A promise for the set password completion.
 */
export declare function setPassword(service: string, account: string, password: string): Promise<void>;

/**
 * Delete the stored password for the service and account.
 *
 * @param service The string service name.
 * @param account The string account name.
 *
 * @returns A promise for the deletion status. True on success.
 */
export declare function deletePassword(service: string, account: string): Promise<boolean>;

/**
 * Find a password for the service in the keychain.
 *
 * @param service The string service name.
 *
 * @returns A promise for the password string.
 */
export declare function findPassword(service: string): Promise<string | null>;

/**
 * Find all accounts and passwords for `service` in the keychain.
 *
 * @param service The string service name.
 *
 * @returns A promise for the array of found credentials.
 */
export declare function findCredentials(service: string): Promise<Array<{ account: string, password: string}>>;
