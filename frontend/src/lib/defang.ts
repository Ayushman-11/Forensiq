/**
 * Forensiq Threat Intelligence IOC Defanging & Utility Library
 */

export type IocType = "ip" | "domain" | "url" | "hash" | "unknown";

const IPV4_REGEX = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
const HASH_REGEX = /^[a-fA-F0-9]{32,64}$/;
const URL_REGEX = /^https?:\/\//i;

/**
 * Detect the logical IOC type from the string representation
 */
export function detectIocType(ioc: string): IocType {
  const clean = ioc.trim();
  if (URL_REGEX.test(clean)) return "url";
  if (IPV4_REGEX.test(clean)) return "ip";
  if (HASH_REGEX.test(clean)) return "hash";
  if (clean.includes(".") && !clean.includes(" ") && !clean.includes("/")) return "domain";
  return "unknown";
}

/**
 * Defang an IOC so it is safe to copy/paste in chat, emails, and documentation
 * e.g., 192.168.1.1 -> 192[.]168[.]1[.]1
 *       http://evil.com/path -> hxxp://evil[.]com/path
 *       malware.xyz -> malware[.]xyz
 */
export function defangIoc(ioc: string): string {
  if (!ioc) return "";
  let defanged = ioc.trim();

  // Defang protocol
  defanged = defanged.replace(/^http:\/\//i, "hxxp://");
  defanged = defanged.replace(/^https:\/\//i, "hxxps://");

  // Defang periods in domain / IP
  defanged = defanged.replace(/\./g, "[.]");

  return defanged;
}

/**
 * Refang a previously defanged IOC back into standard notation
 */
export function refangIoc(defanged: string): string {
  if (!defanged) return "";
  let refanged = defanged.trim();

  refanged = refanged.replace(/^hxxp:\/\//i, "http://");
  refanged = refanged.replace(/^hxxps:\/\//i, "https://");
  refanged = refanged.replace(/\[\.\]/g, ".");
  refanged = refanged.replace(/\[:\]/g, ":");

  return refanged;
}
