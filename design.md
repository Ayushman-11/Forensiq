# Forensiq Detailed UI Design Specification (Grid Dashboard)

## 1. Core Aesthetic & Vibe
**Theme:** "Advanced SOC Grid Dashboard". We are implementing a dense, highly structured 3-column dashboard based on the provided reference image, tailored to the "Forensiq" brand.
**Atmosphere:** A sleek, glassmorphic dark mode. We will use a soft, deep background with distinct, slightly lighter surface cards. The cards will feature generous border radii (`rounded-2xl` or `rounded-3xl`) and subtle inset borders to give them a premium feel.

## 2. Typography
*   **Headers & Primary Numbers:** `Space Grotesk` or `Geist` - Clean, modern, highly legible for large numbers and greetings (e.g., "Good Morning").
*   **Body & UI Text:** `Inter` or `Geist` - Crisp and minimal.
*   **Monospace/Data/IPs:** `Fira Code`.

## 3. Color Palette & Theming (Forensiq Theme)
*   **Void Background:** `#0A0D14` (Deep midnight blue/black).
*   **Surface/Cards:** `#131722` (Slightly elevated dark navy).
*   **Borders:** `rgba(255, 255, 255, 0.05)`.
*   **Primary Accent (Brand/Links):** Cyan/Teal `#00F0FF`. (The reference uses blue, but we will use the Forensiq cyan).
*   **Selected Card State:** A gradient background (e.g., `from-cyan-500/20 to-blue-600/20`) with cyan text.
*   **Severity Colors:**
    *   **Critical:** Crimson `#FF1744`.
    *   **High:** Warning Amber `#FF9100`.
    *   **Medium:** Toxic Green `#00E676`.
    *   **Low/Info:** Electric Blue `#2979FF`.
*   **Text:** Primary `#FFFFFF`, Secondary `#8A95A5`.

## 4. Layout Structure (3 Columns)
The dashboard will use a CSS Grid to create a responsive 3-column layout on desktop:

**Global Header:**
- Left: Forensiq Logo & Brand name.
- Middle: Icon navigation (Dashboard, Security, Team, Logs, Settings).
- Right: Search, Notifications, User Profile, and a "System Status" button (e.g., Green "Secure").

**Greeting:**
- Large "Good Morning, [User]" spanning the top of the content area.

**Column 1 (Left):**
- **Total Threats Gauge:** A semi-circle gauge chart showing total threats, broken down by severity at the bottom.
- **Open Tickets:** A list of active tickets. The active ticket will have an expanded UI with a bright accent background (cyan gradient) containing "View Details" and "Close Ticket" buttons.

**Column 2 (Middle):**
- **Feature Banner:** A wide card with a background image or gradient highlighting "Top Cybersecurity Trends" or "System Health".
- **Threat Tactics Matrix:** A grid of dots (heat map) mapping MITRE Tactics (Collection, Credential Access, etc.) against Dates.

**Column 3 (Right):**
- **Attack Timeline:** A horizontal Gantt-style chart showing threat stages (Reconnaissance, Weaponization) across days of the week.
- **Top Threats List:** A dense list of recent threats showing a severity badge, threat name, severity level, and Source IP.

## 5. Motion & Micro-interactions
*   Cards will slightly scale up on hover.
*   Charts will animate in on load (bars expanding, gauge filling up).
