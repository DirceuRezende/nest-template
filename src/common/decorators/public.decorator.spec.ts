import { Public } from './public.decorator';

describe('Public Decorator', () => {
  it('should be defined', () => {
    expect(Public).toBeDefined();
  });

  describe('Public', () => {
    it('should return isPublic', () => {
      const publicReturn = Public();
      expect(publicReturn.KEY).toBe('isPublic');
    });
  });
});
