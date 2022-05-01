-- AlterTable
ALTER TABLE "users" ADD COLUMN     "email_verified" BOOLEAN DEFAULT false;

-- CreateTable
CREATE TABLE "forgot_passwords" (
    "id" SERIAL NOT NULL,
    "email" VARCHAR(255) NOT NULL,
    "token" VARCHAR(400) NOT NULL,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "forgot_passwords_pkey" PRIMARY KEY ("id")
);
