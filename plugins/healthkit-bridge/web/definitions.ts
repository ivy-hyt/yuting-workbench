export interface HealthKitBridgePlugin {
  isAvailable(): Promise<{ available: boolean }>;
  requestAuthorization(): Promise<{ authorized: boolean }>;
  queryToday(): Promise<any>;
}
