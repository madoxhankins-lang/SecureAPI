import bcrypt from 'bcryptjs';
import { randomUUID } from 'node:crypto';
import { ApiError } from './errors';
export type Role = 'USER' | 'ADMIN';
export interface User { id: string; email: string; passwordHash: string; role: Role }
export const publicUser = ({ id, email, role }: User) => ({ id, email, role });
export class UserStore {
  private readonly users = new Map<string, User>();
  async add(email: string, password: string, role: Role = 'USER'): Promise<User> {
    const passwordHash = await bcrypt.hash(password, 12);
    // Checking after hashing prevents concurrent registrations from overwriting a user.
    if (this.users.has(email)) throw new ApiError(409, 'EMAIL_IN_USE', 'An account already uses this email.');
    const user = { id: randomUUID(), email, passwordHash, role };
    this.users.set(email, user);
    return user;
  }
  byEmail(email: string): User | undefined { return this.users.get(email); }
  byId(id: string): User | undefined { return [...this.users.values()].find(user => user.id === id); }
}
