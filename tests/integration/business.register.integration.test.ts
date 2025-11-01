import request from "supertest";
import app from "../../src/app";
import * as businessService from "../../src/services/business";

jest.mock("../../src/services/business");

const mockGetBusinessByEmail = businessService.getBusinessByEmail as jest.Mock;
const mockGetBusinessByUsername =
  businessService.getBusinessByUsername as jest.Mock;
const mockCreateBusiness = businessService.createBusiness as jest.Mock;

describe("POST /api/businesses/register", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("should return 400 if required fields are missing", async () => {
    const res = await request(app).post("/api/businesses/register").send({
      email: "test@example.com",
      // missing name, username, category, password
    });

    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/Faltan datos necesarios/i);
  });

  it("should return 400 for invalid email", async () => {
    const res = await request(app).post("/api/businesses/register").send({
      email: "invalid-email",
      name: "Test Business",
      busi_username: "testbiz",
      category: "food",
      password: "Password1",
    });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe("Email inválido");
  });

  it("should return 400 if password is too short", async () => {
    const res = await request(app).post("/api/businesses/register").send({
      email: "test@example.com",
      name: "Biz",
      busi_username: "testbiz",
      category: "food",
      password: "123",
    });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe(
      "La contraseña debe tener al menos 8 caracteres",
    );
  });

  it("should return 400 if password does not contain letters and numbers", async () => {
    const res = await request(app).post("/api/businesses/register").send({
      email: "test@example.com",
      name: "Biz",
      busi_username: "testbiz",
      category: "food",
      password: "onlyletters",
    });

    expect(res.status).toBe(400);
    expect(res.body.error).toBe(
      "La contraseña debe contener al menos una letra y un número",
    );
  });

  it("should return 409 if email or username already exist", async () => {
    mockGetBusinessByEmail.mockResolvedValueOnce({ id: 1 });
    mockGetBusinessByUsername.mockResolvedValueOnce(null);

    const res = await request(app).post("/api/businesses/register").send({
      email: "duplicate@example.com",
      name: "Biz",
      busi_username: "testbiz",
      category: "food",
      password: "Password1",
    });

    expect(mockGetBusinessByEmail).toHaveBeenCalledWith(
      "duplicate@example.com",
    );
    expect(res.status).toBe(409);
    expect(res.body.error).toBe(
      "El email o nombre de usuario ya está registrado",
    );
  });

  it("should return 201 and business data when registration succeeds", async () => {
    mockGetBusinessByEmail.mockResolvedValueOnce(null);
    mockGetBusinessByUsername.mockResolvedValueOnce(null);
    mockCreateBusiness.mockResolvedValueOnce({
      id: "biz123",
      name: "Biz Success",
      busi_username: "biz_succ",
      email: "biz@example.com",
      category: "food",
      description: "Great business",
      address: "123 Street",
    });

    const res = await request(app).post("/api/businesses/register").send({
      email: "biz@example.com",
      name: "Biz Success",
      busi_username: "biz_succ",
      category: "food",
      rating: 5,
      description: "Great business",
      address: "123 Street",
      password: "Password1",
    });

    expect(mockCreateBusiness).toHaveBeenCalled();
    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({
      id: "biz123",
      name: "Biz Success",
      email: "biz@example.com",
      category: "food",
    });
  });

  it("should return 500 if an unexpected error occurs", async () => {
    mockGetBusinessByEmail.mockRejectedValueOnce(new Error("Database error"));

    const res = await request(app).post("/api/businesses/register").send({
      email: "error@example.com",
      name: "Error Biz",
      busi_username: "errorbiz",
      category: "food",
      password: "Password1",
    });

    expect(res.status).toBe(500);
    expect(res.body.error).toBe("Database error");
  });
});
