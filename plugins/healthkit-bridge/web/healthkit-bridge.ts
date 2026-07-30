import { WebPlugin } from '@capacitor/core';

import type { HealthKitBridgePlugin } from './definitions';

export class HealthKitBridgeWeb extends WebPlugin implements HealthKitBridgePlugin {
  async isAvailable(): Promise<{ available: boolean }> {
    return { available: false };
  }
  async requestAuthorization(): Promise<{ authorized: boolean }> {
    return { authorized: false };
  }
  async queryToday(): Promise<any> {
    return { date: '' };
  }
}
