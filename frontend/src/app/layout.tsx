import type { Metadata } from "next";
import { Geist, JetBrains_Mono } from "next/font/google";
import Link from "next/link";
import AppLayout from "@/components/AppLayout";
import "./globals.css";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-jetbrains-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "Forensiq - SOC Dashboard",
  description: "AI Security Ops",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="en"
      className={`${geistSans.variable} ${jetbrainsMono.variable} h-full antialiased`}
    >
      <head>
        <link
          href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL,GRAD,opsz@400,0,0,24&display=swap"
          rel="stylesheet"
        />
      </head>
      <body className="min-h-screen overflow-x-hidden selection:bg-primary-container selection:text-on-primary-container bg-background text-on-surface flex">
        <AppLayout>
          {children}
        </AppLayout>
      </body>
    </html>
  );
}
