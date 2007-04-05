#ifndef LIBWHEEL_TRIE_IMPL_CPP
    #define LIBWHEEL_TRIE_IMPL_CPP
    
    #include "Trie.hpp"

namespace Libwheel
{

UninitializedException::UninitializedException(const std::string& s)
: runtime_error(s)
{}

template <typename CharType, typename MatchType>
Trie<CharType, MatchType>::Node::Node()
: match(NULL), transitions()
{}

template <typename CharType, typename MatchType>
Trie<CharType, MatchType>::Trie()
: tree()
{
    Node node;
    tree.push_back(node);
}

template <typename CharType, typename MatchType>
Trie<CharType, MatchType>::~Trie()
{}

template <typename CharType, typename MatchType>
void
Trie<CharType, MatchType>::addString(const StringType& str, const MatchType& match)
{
    Node* cur;
    Node* next = &(*tree.begin());
    typename Node::TransitionsType::iterator transition;
    
    for (typename StringType::const_iterator i=str.begin(); i!=str.end(); ++i)
    {
        cur = next;
        
        transition = cur->transitions.find(*i);
        if (transition == cur->transitions.end())
        {
            // we don't have this character; add it
            Node node;
            tree.push_back(node);
            next = &(*(--tree.end()));
            cur->transitions.insert(std::pair<CharType, Node*>(*i, next));
        }
        else
        {
            // we already have this character; move on to the next
            next = transition->second;
        }
    }

    // we're now at the end node for this string
    // fail silently if there's already a match here
    if (next->match == NULL)
        next->match = &match;
}

/*template <typename CharType, typename MatchType>
const typename Trie<CharType, MatchType>::Node* 
Trie<CharType, MatchType>::getInitialState() const
{
    return &(*tree.begin());
}*/


template <typename CharType, typename MatchType>
const MatchType*
Trie<CharType, MatchType>::search(const StringType& str) const
{
    const Node* cur = &(*tree.begin());
    typename Node::TransitionsType::const_iterator transition;
    
    // follow the tree
    for (typename StringType::const_iterator i=str.begin(); i!=str.end(); ++i)
    {
        transition = cur->transitions.find(*i);
        if (transition == cur->transitions.end())
            return NULL;
        else
            cur = transition->second;
    }
    
    // return the match, if there is one
    return cur->match;
}

template <typename CharType, typename MatchType>
const MatchType* 
Trie<CharType, MatchType>::search(const CharType* str, size_t strlen) const
{
    const Node* cur = &(*tree.begin());
    typename Node::TransitionsType::const_iterator transition;
    
    assert(str != NULL);
    
    // follow the tree
    for (unsigned i=0; i<strlen; i++)
    {
        transition = cur->transitions.find(str[i]);
        if (transition == cur->transitions.end())
            return NULL;
        else
            cur = transition->second;
    }
    
    // return the match, if there is one
    return cur->match;
}

} // namespace Libwheel


#if 0

#include <iostream>
#include <boost/cstdint.hpp>

int main()
{
    Libwheel::Trie<boost::uint16_t, std::string> tree;
    const std::string* str;
    std::vector<boost::uint16_t> vec1;
    std::vector<boost::uint16_t> vec2;
    std::vector<boost::uint16_t> vec3;
    std::vector<boost::uint16_t> vec4;
    std::string str1 = "123";
    std::string str2 = "124";
    std::string str3 = "312";

    vec1.push_back(1);
    vec1.push_back(2);
    vec1.push_back(3);
    vec2.push_back(1);
    vec2.push_back(2);
    vec2.push_back(4);
    vec3.push_back(3);
    vec3.push_back(1);
    vec3.push_back(2);
    vec3.push_back(1);
    vec3.push_back(2);
    vec3.push_back(2);

    tree.addString(vec1, str1);
    tree.addString(vec2, str2);
    tree.addString(vec3, str3);

    str = tree.search(vec1);
    if (str)
        std::cout << "found " << *str << std::endl;
    str = tree.search(vec2);
    if (str)
        std::cout << "found " << *str << std::endl;
    str = tree.search(vec3);
    if (str)
        std::cout << "found " << *str << std::endl;
    str = tree.search(vec4);
    if (str)
        std::cout << "found " << *str << std::endl;

    
    return 0;
}
    
#endif

#endif /* LIBWHEEL_TRIE_IMPL_CPP */
