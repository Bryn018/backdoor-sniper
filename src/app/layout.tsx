import type { Metadata } from "next";
import { Geist, Geist_Mono } from "next/font/google";
import "./globals.css";
import { Toaster } from "@/components/ui/sonner";
import { ThemeProvider } from "next-themes";

const geistSans = Geist({
  variable: "--font-geist-sans",
  subsets: ["latin"],
});

const geistMono = Geist_Mono({
  variable: "--font-geist-mono",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "BackdoorSniper — Python Backdoor Detector",
  description:
    "Static analysis tool that scans Python source code for backdoors, reverse shells, obfuscated payloads, credential stealers and persistence mechanisms.",
  keywords: [
    "Python",
    "backdoor",
    "malware analysis",
    "static analysis",
    "security",
    "reverse shell",
    "code scanner",
  ],
  authors: [{ name: "BackdoorSniper" }],
  icons: {
    icon: "/favicon.svg",
  },
  openGraph: {
    title: "BackdoorSniper — Python Backdoor Detector",
    description:
      "Scan Python source for backdoors, reverse shells, obfuscated payloads and persistence mechanisms.",
    type: "website",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body
        className={`${geistSans.variable} ${geistMono.variable} antialiased bg-background text-foreground`}
      >
        <ThemeProvider
          attribute="class"
          defaultTheme="dark"
          enableSystem
          disableTransitionOnChange
        >
          {children}
          <Toaster />
        </ThemeProvider>
      </body>
    </html>
  );
}
