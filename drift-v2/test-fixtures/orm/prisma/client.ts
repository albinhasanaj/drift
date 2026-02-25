// Prisma client usage
import { PrismaClient } from "@prisma/client";

const prisma = new PrismaClient();

export async function getUser(id: string) {
  return prisma.user.findUnique({ where: { id } });
}

export async function createUser(data: { email: string; password: string; name: string }) {
  return prisma.user.create({ data });
}
