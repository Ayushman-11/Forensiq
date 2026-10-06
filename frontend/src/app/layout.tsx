import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import AppLayout from "@/components/AppLayout";
import { AuthProvider } from "@/context/AuthContext";
import { ThemeProvider } from "@/context/ThemeContext";
import AuthGuard from "@/components/AuthGuard";
import "./globals.css";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-jetbrains-mono",
  subsets: ["latin"],
  display: "swap",
});

export const metadata: Metadata = {
  title: "FORENSIQ — AI Security Operations Platform",
  description: "Real-time threat detection, investigation and response.",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`${inter.variable} ${jetbrainsMono.variable} dark h-full antialiased`}
      suppressHydrationWarning
    >
      <body className="min-h-screen overflow-x-hidden bg-[var(--bg-app)] text-[var(--text-primary)] flex font-sans">
        <ThemeProvider>
          <AuthProvider>
            <AuthGuard>
              <AppLayout>{children}</AppLayout>
            </AuthGuard>
          </AuthProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
