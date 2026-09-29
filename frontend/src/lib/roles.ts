export const ROLE_LABELS: Record<string, string> = {
  soc_analyst: "SOC L1",
  soc_manager: "SOC Manager",
  admin: "Splunk Admin",
};

export function roleLabel(role: string): string {
  return ROLE_LABELS[role] ?? role;
}
