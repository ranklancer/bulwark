import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

// Standard shadcn cn helper. Combines clsx's conditional class composition
// with tailwind-merge's last-wins resolution for conflicting Tailwind
// utility classes ("p-2 p-4" → "p-4"). Used by every shadcn-generated
// component — landing it now keeps 16c's `npx shadcn add` painless.
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
