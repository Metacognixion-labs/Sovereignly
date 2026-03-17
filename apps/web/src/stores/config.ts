"use client";

import { create } from "zustand";
import { persist } from "zustand/middleware";

interface ConfigState {
  endpoint: string;
  adminToken: string;
  jwtToken: string;
  setEndpoint: (url: string) => void;
  setAdminToken: (token: string) => void;
  setJwtToken: (token: string) => void;
  clear: () => void;
}

export const useStore = create<ConfigState>()(
  persist(
    (set) => ({
      endpoint: "",
      adminToken: "",
      jwtToken: "",
      setEndpoint: (endpoint) => set({ endpoint }),
      setAdminToken: (adminToken) => set({ adminToken }),
      setJwtToken: (jwtToken) => set({ jwtToken }),
      clear: () => set({ endpoint: "", adminToken: "", jwtToken: "" }),
    }),
    { name: "sovereignly-config" }
  )
);
