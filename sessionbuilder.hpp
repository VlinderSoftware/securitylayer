#ifndef dnp3sav6_sessionbuilder_hpp
#define dnp3sav6_sessionbuilder_hpp

namespace DNP3SAv6 {
class SessionBuilder
{
public :
	SessionBuilder();
	~SessionBuilder() = default;
	
	SessionBuilder(SessionBuilder &&other) noexcept = default;
	SessionBuilder& operator=(SessionBuilder &&other) noexcept = default;
	SessionBuilder(SessionBuilder const&) = delete;
	SessionBuilder& operator=(SessionBuilder const&) = delete;

	virtual void reset() noexcept override;
};
}

#endif



