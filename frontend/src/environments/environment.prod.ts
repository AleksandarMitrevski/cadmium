import { TransitiveCompileNgModuleMetadata } from "@angular/compiler";

export const environment = {
  production: TransitiveCompileNgModuleMetadata,
  appBackend: "http://localhost:8000"
};
