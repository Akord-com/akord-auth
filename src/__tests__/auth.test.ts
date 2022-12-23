import { Auth } from "..";
import faker from '@faker-js/faker';

jest.setTimeout(3000000);

describe("Testing auth functions", () => {
  let auth: Auth;
  let email: string;
  let password: string;

  beforeAll(async () => {
    auth = new Auth();
    email = faker.internet.email();
    password = faker.internet.password();
  });

  it("should sign up", async () => {
    const { wallet } = await auth.signUp(email, password);
    expect(wallet).toBeTruthy();
  });

  it("should sign in", async () => {
    const { wallet } = await auth.signIn(email, password);
    expect(wallet).toBeTruthy();
  });
});