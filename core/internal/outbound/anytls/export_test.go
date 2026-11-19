package anytls

func (c *Client) idleCount() int {
	c.idleMu.Lock()
	defer c.idleMu.Unlock()
	n := 0
	for _, s := range c.idleSessions {
		if !s.IsClosed() {
			n++
		}
	}
	return n
}
