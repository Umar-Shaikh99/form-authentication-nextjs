import db from "./db";

//Pushing the data into db if all error checks is passed
export function createUser(email, password) {
  const result = db
    .prepare("INSERT INTO users (email,password) VALUES (?,?)")
    .run(email, password);
  return result.lastInsertRowid;
}

export function getUserByEmail(email) {
  return db.prepare("SELECT * FROM users WHERE email = ?").get(email);
}
