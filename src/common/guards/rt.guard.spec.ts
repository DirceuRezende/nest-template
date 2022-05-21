import { RtGuard } from './rt.guard';

describe('AuthenticatedGuard', () => {
  let rtGuard: RtGuard;

  beforeEach(() => {
    rtGuard = new RtGuard();
  });

  it('should be defined', () => {
    expect(rtGuard).toBeDefined();
  });
});
