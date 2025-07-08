import NextAuth, { DefaultSession, NextAuthResult, Session } from "./auth";
import authConfig from "./config";
import { logger } from "@repo/logger";
import { redirect } from "next/navigation";
import { DrizzleAdapter } from "@auth/drizzle-adapter";
import db from "@repo/db";
import {
  User,
  usersTable,
  accountsTable,
  sessionsTable,
  verificationTokensTable,
  authenticatorsTable,
} from "@repo/db/schema";

const log = logger.child({ context: "auth" });

declare module "next-auth" {
  interface Session extends DefaultSession {
    user: {
      organizationId: number;
    } & DefaultSession["user"];
  }
}

log.info({ providers: authConfig.providers.map((p) => p?.name) }, "Auth config");

const result: NextAuthResult = NextAuth({
  adapter: DrizzleAdapter(db, {
    usersTable,
    accountsTable,
    sessionsTable,
    verificationTokensTable,
    authenticatorsTable,
  }),
  ...authConfig,
  callbacks: {
    /** Extends the session.user object to keep also the id and organizationId values */
    session({ session, token }) {
      session.user.id = token.sub as string;
      session.user.organizationId = token.orgId as number;
      return session;
    },

    /** Extends the JWT token to keep also the orgId value */
    async jwt({ token, account, user }) {
      if (account && user && "organizationId" in user) {
        log.info({ user }, "New user registered");
        if (!user.organizationId) {
          const defaultOrg = await db.query.organizationsTable.findFirst();
          if (defaultOrg) {
            user.organizationId = defaultOrg.id;
            await db.insert(usersTable).values({
              where: { id: user.id },
              data: { organizationId: defaultOrg.id },
            });
          }
        }
        token.orgId = user.organizationId;
      }
      return token;
    },
  },
  logger: {
    error(error) {
      log.error(error);
    },
    warn(code) {
      log.warn(code);
    },
    debug(message, meta: any) {
      log.trace({ ...meta }, message);
    },
  },
});
export const handlers: NextAuthResult["handlers"] = result.handlers;
export const signIn: NextAuthResult["signIn"] = result.signIn;
export const signOut: NextAuthResult["signOut"] = result.signOut;
export const auth: NextAuthResult["auth"] = result.auth;

export async function authOrLogin(): Promise<Session> {
  // Bypass authentication: always return a fake session
  return {
    user: {
      id: "1",
      email: "test@example.com",
      name: "Test User",
      organizationId: 1,
    },
    expires: "2099-12-31T23:59:59.999Z",
  } as Session;
}

