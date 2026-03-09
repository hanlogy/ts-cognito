import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';

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

export class JsonFileStorage {
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

  public findById(id: string): LocalCognitoUserRecord | undefined {
    return this.data.find((item) => {
      return item.user.id === id;
    });
  }

  public findByUsername(username: string): LocalCognitoUserRecord | undefined {
    return this.data.find((item) => {
      return item.user.username === username;
    });
  }

  public findByRefreshToken(
    refreshToken: string,
  ): LocalCognitoUserRecord | undefined {
    return this.data.find((item) => {
      return item.auth?.refreshToken === refreshToken;
    });
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

  public add(item: LocalCognitoUserRecord): void {
    const existedUser = this.findById(item.user.id);
    if (existedUser) {
      throw new Error(`User already exists: ${item.user.id}`);
    }

    this.data.push(item);
    this.save();
  }

  public update(item: LocalCognitoUserRecord): void {
    const index = this.data.findIndex((currentItem) => {
      return currentItem.user.id === item.user.id;
    });

    if (index === -1) {
      throw new Error(`User not found: ${item.user.id}`);
    }

    this.data[index] = item;
    this.save();
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
