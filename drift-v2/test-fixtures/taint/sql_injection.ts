// TAINT: source=line:6:col:22 sink=line:7:col:14
// Known taint path: req.query → db.query() (SQL injection)

import { Request, Response } from "express";

export function getUser(req: Request, res: Response) {
  const userId = req.query.id;  // SOURCE: user-controlled input
  const result = db.query(`SELECT * FROM users WHERE id = '${userId}'`);  // SINK: SQL injection
  res.json(result);
}
