"use client";

import { create } from "zustand";
import { persist } from "zustand/middleware";

interface ConfigState {
  endpoint: string;
  setEndpoint: (url: string) => void;
  clear: () => void;
}

export const useStore = create<ConfigState>()(
  persist(
    (set) => ({
      endpoint: "",
      setEndpoint: (endpoint) => set({ endpoint }),
      clear: () => set({ endpoint: "" }),
    }),
    { name: "sovereignly-config" }
  )
);
