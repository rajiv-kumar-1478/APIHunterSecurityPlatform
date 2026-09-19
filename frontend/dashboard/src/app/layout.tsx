import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "APIHunter Security Platform",
  description: "Security intelligence platform for API key discovery, analysis, and vulnerability management",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body className="antialiased">{children}</body>
    </html>
  );
}
