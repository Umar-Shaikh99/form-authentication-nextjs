import { Lucia } from "lucia";
import { BetterSqlite3Adapter } from "@lucia-auth/adapter-sqlite";
import db from "./db";
import { cookies } from "next/headers";

const adapter = new BetterSqlite3Adapter(db, {
  user: "users",
  session: "sessions",
});

//initialize Lucia auth
const lucia = new Lucia(adapter, {
  sessionCookie: {
    expires: false,
    attributes: {
      secure: process.env.NODE_ENV === "production",
    },
  },
});

//Creating Session cookies for outgoing request.. the cookies() is a default function available in nextjs
//cookies().set() this will create the cookies using name,value or attribute any one of them
export async function createAuthSession(userId) {
  const session = await lucia.createSession(userId, {});
  const sessionCookie = lucia.createSessionCookie(session.id);
  cookies().set(
    sessionCookie.name,
    sessionCookie.value,
    sessionCookie.attributes
  );
}

export async function verifyAuth() {
  const sessionCookie = cookies().get(lucia.sessionCookieName);

  if (!sessionCookie) {
    return {
      user: null,
      session: false,
    };
  }

  //check for if there is sessionn cookie are there or not if there is no session we can return null obj()
  const sessionId = sessionCookie.value;
  if (!sessionId) {
    return {
      user: null,
      session: null,
    };
  }

  const result = await lucia.validateSession(sessionId); //if the session is valid we can refresh the session and recreate the new active session cookie
  try {
    if (result.session && result.session.fresh) {
      const sessionCookie = lucia.createSessionCookie(result.session.id);
      cookies().set(
        sessionCookie.name,
        sessionCookie.value,
        sessionCookie.attributes
      );
    }
    if (!result.session) {
      //if the result doest not containing any session we can create the new blanksessioncookie and delete the existiing invalid cookie
      const sessionCookie = lucia.createBlankSessionCookie();
      cookies().set(
        sessionCookie.name,
        sessionCookie.value,
        sessionCookie.attributes
      );
    }
  } catch {}
  return result;
}

export async function destroySession() {
  const { session } = await verifyAuth();
  if (!session) {
    return {
      error: "Unathorized!",
    };
  }

  await lucia.invalidateSession(session.id);

  const sessionCookie = lucia.createBlankSessionCookie();
  cookies().set(
    sessionCookie.name,
    sessionCookie.value,
    sessionCookie.attributes
  );
}
