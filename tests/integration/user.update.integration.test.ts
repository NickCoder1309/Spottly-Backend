// tests/integration/user.update.integration.test.ts
import request from "supertest";
import app from "../../src/app";
import * as userService from "../../src/services/user";
import bcrypt from "bcrypt";

jest.mock("../../src/services/user");
jest.mock("bcrypt");

const mockUpdateUser = userService.updateUser as jest.Mock;
const mockHash = bcrypt.hash as jest.Mock;

describe("PUT /api/users/updateUser/:userId - integration", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("should update user successfully", async () => {
    const fakeUpdatedUser = {
      id: "1",
      name: "Jane",
      email: "jane@example.com",
    };
    mockUpdateUser.mockResolvedValueOnce(fakeUpdatedUser);

    const res = await request(app)
      .put("/api/users/updateUser/1")
      .send({ name: "Jane", email: "jane@example.com" });

    expect(res.status).toBe(200);
    expect(res.body.message).toMatch(/update successful/i);
    expect(res.body.updatedUser).toEqual(fakeUpdatedUser);
  });

  it("should hash password before updating", async () => {
    mockHash.mockResolvedValueOnce("supersecurehash");
    const fakeUpdatedUser = {
      id: "2",
      password: "supersecurehash",
    };
    mockUpdateUser.mockResolvedValueOnce(fakeUpdatedUser);

    const res = await request(app)
      .put("/api/users/updateUser/2")
      .send({ password: "newpassword123" });

    expect(mockHash).toHaveBeenCalledWith("newpassword123", 10);
    expect(res.status).toBe(200);
    expect(res.body.updatedUser.password).toBe("supersecurehash");
  });

  it("should return 500 if updateUser throws", async () => {
    mockUpdateUser.mockRejectedValueOnce(new Error("DB connection error"));

    const res = await request(app)
      .put("/api/users/updateUser/123")
      .send({ name: "Fail Test" });

    expect(res.status).toBe(500);
    expect(res.body.error).toMatch(/db connection error/i);
  });
});
