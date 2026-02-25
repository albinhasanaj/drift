# ActiveRecord model with sensitive fields
class User < ApplicationRecord
  has_many :posts

  validates :email, presence: true, uniqueness: true  # SENSITIVE
  validates :password, presence: true  # SENSITIVE
  validates :name, presence: true

  # ssn is a sensitive field  # SENSITIVE
  encrypts :ssn

  enum role: { user: 0, admin: 1 }
end
