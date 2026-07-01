const { expressMiddleware } = require('../src/detector');

describe('Benign Traffic Benchmark (False Positives)', () => {
  let mockNext;
  let mockRes;
  let middleware;

  beforeEach(() => {
    mockNext = jest.fn();
    mockRes = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn()
    };
    // Use the default threshold for real world testing
    middleware = expressMiddleware(); 
  });

  const benignPayloads = [
    "Please select your favorite color from the union of these two sets.",
    "My name is O'Brien.",
    "Drop table near the window.",
    "I need an update on my order.",
    "Wait for me at the station.",
    "The sleep number bed is great.",
    "We need to insert into the document.",
    "And then I said, 'Wow, that is cool'.",
    "He's 5'9\" tall.",
    "Math equation: 1=1 is always true, but what about 2=2?",
    "If x = 1 and y = 1 then x = y.",
    "Can you delay the meeting by 5 minutes?",
    "Here is my javascript homework.",
    "The script for the play is attached.",
    "I'll embed the video in the iframe.",
    "The union of workers has announced a strike.",
    "An object in motion stays in motion.",
    "Please drop by my office later.",
    "The new update is available for download.",
    "I love writing in plain text.",
    "Select all the images that contain a crosswalk.",
    "He left a comment -- it was very helpful."
  ];

  it('should not block any of the 20+ benign payloads', async () => {
    let ipCounter = 1;
    for (const payload of benignPayloads) {
      const req = { body: { text: payload }, ip: `10.0.0.${ipCounter++}` };
      await middleware(req, mockRes, mockNext);
    }
    expect(mockRes.status).not.toHaveBeenCalled();
    expect(mockNext).toHaveBeenCalledTimes(benignPayloads.length);
  });
});
