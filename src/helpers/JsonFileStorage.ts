import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import type { Storage } from './Storage';

export interface LocalCognitoUserRecord {
  user: {
    id: string;
    username: string;
    password: string;
    confirmed: boolean;
    attributes: Record<string, string>;
  };
  auth?: {
    refreshToken?: string;
    expiresIn?: number;
  };
  signUpCode?: string;
  forgotPasswordCode?: string;
  verifyUserAttributeCodes?: Record<string, string>;
}

export class JsonFileStorage implements Storage<LocalCognitoUserRecord> {
  constructor({ filePath }: { filePath?: string | undefined } = {}) {
    this.filePath =
      filePath ?? resolve(process.cwd(), '.cognito-user-local.json');

    if (!existsSync(this.filePath)) {
      writeFileSync(this.filePath, '[]', 'utf8');
    }

    this.data = this.loadData();
  }

  private readonly filePath: string;
  private data: LocalCognitoUserRecord[] = [];

  get(key: string): Promise<LocalCognitoUserRecord | undefined> {
    return Promise.resolve(this.data.find((item) => item.user.id === key));
  }

  put(key: string, value: LocalCognitoUserRecord): Promise<void> {
    const index = this.data.findIndex((item) => item.user.id === key);

    if (index === -1) {
      this.data.push(value);
    } else {
      this.data[index] = value;
    }

    this.save();

    return Promise.resolve();
  }

  delete(key: string): Promise<void> {
    this.data = this.data.filter((item) => item.user.id !== key);
    this.save();

    return Promise.resolve();
  }

  list(): Promise<LocalCognitoUserRecord[]> {
    return Promise.resolve(this.data);
  }

  private loadData(): LocalCognitoUserRecord[] {
    const content = readFileSync(this.filePath, 'utf8');
    const parsed: unknown = JSON.parse(content);

    if (!Array.isArray(parsed)) {
      throw new Error('JsonFileStorage file content must be an array');
    }

    return parsed.filter((item): item is LocalCognitoUserRecord => {
      return this.isLocalCognitoData(item);
    });
  }

  private isLocalCognitoData(value: unknown): value is LocalCognitoUserRecord {
    if (!this.isRecord(value)) {
      return false;
    }

    if (!this.isRecord(value.user)) {
      return false;
    }

    if (!this.isRecord(value.user.attributes)) {
      return false;
    }

    return (
      typeof value.user.id === 'string' &&
      typeof value.user.username === 'string' &&
      typeof value.user.password === 'string' &&
      typeof value.user.confirmed === 'boolean'
    );
  }

  private isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null;
  }

  private save(): void {
    writeFileSync(this.filePath, JSON.stringify(this.data, null, 2), 'utf8');
  }
}
