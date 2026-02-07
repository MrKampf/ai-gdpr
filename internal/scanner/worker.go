package scanner

func (s *Scanner) worker(id int) {
	defer s.wg.Done()

	for job := range s.jobs {
		select {
		case <-s.ctx.Done():
			return
		default:
			result := s.scanFile(job.FilePath)
			s.results <- result
		}
	}
}
