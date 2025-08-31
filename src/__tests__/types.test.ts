import { BlitzWareAuthError } from '../types';

describe('BlitzWareAuthError', () => {
  it('should create error with message and code', () => {
    const error = new BlitzWareAuthError('Test message', 'test_code');
    
    expect(error.message).toBe('Test message');
    expect(error.code).toBe('test_code');
    expect(error.name).toBe('BlitzWareAuthError');
    expect(error).toBeInstanceOf(Error);
  });

  it('should create error with details', () => {
    const details = { field: 'test', value: 123 };
    const error = new BlitzWareAuthError('Test message', 'test_code', details);
    
    expect(error.details).toEqual(details);
  });

  it('should create error without details', () => {
    const error = new BlitzWareAuthError('Test message', 'test_code');
    
    expect(error.details).toBeUndefined();
  });
});
