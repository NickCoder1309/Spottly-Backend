import request from "supertest";
import app from "../../src/app";
import * as businessService from "../../src/services/business";
import bcrypt from "bcrypt";
import { generateToken } from "../../src/services/auth";

jest.mock("../../src/services/business");
jest.mock("bcrypt");
jest.mock("../../src/services/auth");

const mockGetBusinessByEmail = businessService.getBusinessByEmail as jest.Mock;
const mockCompare = bcrypt.compare as jest.Mock;
const mockGenerateToken = generateToken as jest.Mock;

describe("POST /api/businesses/login", () => {
  beforeEach(() => jest.clearAllMocks());

  it("should login successfully", async () => {
    mockGetBusinessByEmail.mockResolvedValueOnce({
      id: "1",
      email: "biz@example.com",
      username: "mybiz",
      name: "My Biz",
      password: "hashedpass",
      busi_username: "mybiz",
      category: "Restaurant",
      rating: 4,
      description: "Tasty food",
      address: "123 Main St",
    });
    mockCompare.mockResolvedValueOnce(true);
    mockGenerateToken.mockReturnValue("fake-token");

    const response = await request(app).post("/api/businesses/login").send({
      email: "biz@example.com",
      password: "correctpass",
    });

    expect(response.status).toBe(200);
    expect(response.body.token).toBe("fake-token");
    expect(response.body.user.email).toBe("biz@example.com");
  });

  it("should return 400 if password incorrect", async () => {
    mockGetBusinessByEmail.mockResolvedValueOnce({
      id: "1",
      email: "biz@example.com",
      username: "mybiz",
      name: "My Biz",
      password: "hashedpass",
    });
    mockCompare.mockResolvedValueOnce(false);

    const response = await request(app).post("/api/businesses/login").send({
      email: "biz@example.com",
      password: "wrong",
    });

    expect(response.status).toBe(400);
    expect(response.body.error).toMatch(/incorrect password/i);
  });
});
